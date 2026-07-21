# external module imports
from imports import (fields, fuzz, Dict, List, Tuple)
# get global state objects (CONFIG and TUI)
from globals import get_config
CONFIG = get_config()
# local module imports
from utils import (
    extra_fields_for_comparison,
    log,
    normalise_finding_record,
    normalise_text_for_matching,
)
from model import Finding, Observation

MergeRecord = Finding | Observation


def _normalise_records_before_matching(*record_lists: List[MergeRecord]) -> None:
    """Normalise complete records in-place before any matching comparison.

    Matching can receive records that were constructed outside the JSON import
    path, and nested values are not covered by top-level import normalisation.
    Applying the existing recursive routine at this boundary guarantees that
    every candidate is scored using the same canonical representation.
    """
    for record_list in record_lists:
        for record in record_list:
            normalise_finding_record(record)

def score_finding_similarity(finding_left: Finding, finding_right: Finding) -> float:
    """
    Computes a similarity score between two findings.
    Title match is weighted heavily, with optional fallback to description.
    Returns a float between 0.0 and 100.0.
    """
    log("DEBUG", f"Scoring similarity between Finding Left (ID: {finding_left.id}) and Finding Right (ID: {finding_right.id})", prefix="MATCHING")

    # Retrieve configurable weightings for each component from the loaded config
    # These determine how much influence title, description, and finding_type have on the final score
    raw_weights = {
        "common": CONFIG.get("match_weight_common", 0.05),
        "title": CONFIG.get("match_weight_title", 0.3),
        "type": CONFIG.get("match_weight_finding_type", 0.1),
        "desc": CONFIG.get("match_weight_description", 0.2),
        "impact": CONFIG.get("match_weight_impact", 0.2),
        "mitigation": CONFIG.get("match_weight_mitigation", 0.2),
    }
    log("DEBUG", f"Raw weights: title={raw_weights['title']:.2f}, type={raw_weights['type']:.2f}, desc={raw_weights['desc']:.2f}, impact={raw_weights['impact']:.2f}, mitigation={raw_weights['mitigation']:.2f}", prefix="MATCHING")

    # balances the weights, if they add up to more than 1
    total_weights = sum(raw_weights.values())
    weights = raw_weights.copy()
    if total_weights > 1:
        normalised_weights = {k: v/total_weights for k, v in raw_weights.items()}
        weights = normalised_weights

    log("DEBUG", f"Normalised weights: title={weights['title']:.2f}, type={weights['type']:.2f}, desc={weights['desc']:.2f}, impact={weights['impact']:.2f}, mitigation={weights['mitigation']:.2f}",prefix="MATCHING")

    # Title similarity using token sort ratio (handles reordering well)
    title_left = normalise_text_for_matching(finding_left.title)
    title_right = normalise_text_for_matching(finding_right.title)
    title_score_no_weight = fuzz.token_set_ratio(title_left, title_right)
    title_score = title_score_no_weight * weights['title']
    log("DEBUG", f"Title scores between '{finding_left.title}' and '{finding_right.title}': raw {title_score_no_weight:.2f}, weighted {title_score:.2f}", prefix="MATCHING")
    if title_score_no_weight < CONFIG.get("match_min_threshold_title"):
        log("DEBUG", f"Title below min threshold, so skipping further fuzzy matching", prefix="MATCHING")
        return title_score

    # Finding_type similarity
    type_score = 0
    if finding_left.finding_type and finding_right.finding_type:
        type_score_no_weight = 100 if finding_left.finding_type == finding_right.finding_type and finding_left.finding_type else 0
        type_score = type_score_no_weight * weights['type']
        log("DEBUG", f"Finding types: A='{finding_left.finding_type}' B='{finding_right.finding_type}' → Type weighted score: {type_score:.2f}", prefix="MATCHING")
    else:
        log("DEBUG", "At least one finding is missing a finding_type. Type score is 0", prefix="MATCHING")

    # Description similarity scoring
    desc_score = 0
    if finding_left.description and finding_right.description:
        desc_score_no_weight = fuzz.token_set_ratio(
            normalise_text_for_matching(finding_left.description),
            normalise_text_for_matching(finding_right.description),
        )
        desc_score = desc_score_no_weight * weights['desc']
        log("DEBUG", f"Description weighted score between Finding Left and Right: {desc_score:.2f}", prefix="MATCHING")
    else:
        log("DEBUG", "At least one finding is missing an description. Description score is 0", prefix="MATCHING")

    # Impact similarity scoring
    impact_score = 0
    if finding_left.impact and finding_right.impact:
        impact_score_no_weight = fuzz.token_set_ratio(
            normalise_text_for_matching(finding_left.impact),
            normalise_text_for_matching(finding_right.impact),
        )
        impact_score = impact_score_no_weight * weights['impact']
        log("DEBUG", f"Impact weighted score between Finding Left and Right: {impact_score:.2f}", prefix="MATCHING")
    else:
        log("DEBUG", "At least one finding is missing an impact. Impact score is 0", prefix="MATCHING")

    # Mitigation similarity scoring
    mitigation_score = 0
    if finding_left.mitigation and finding_right.mitigation:
        mitigation_score_no_weight = fuzz.token_set_ratio(
            normalise_text_for_matching(finding_left.mitigation),
            normalise_text_for_matching(finding_right.mitigation),
        )
        mitigation_score = mitigation_score_no_weight * weights['mitigation']
        log("DEBUG", f"Mitigation weighted score between Finding Left and Right: {mitigation_score:.2f}", prefix="MATCHING")
    else:
        log("DEBUG", "At least one finding is missing a mitigation. Mitigation score is 0", prefix="MATCHING")

################################################################################
#        {                                                                     #
#            "id": self.id,                                                    #
#            "severity": self.severity,                                        #
#            "cvss_score": self.cvss_score,                                    #
#            "cvss_vector": self.cvss_vector,                                  #
#            "finding_type": self.finding_type,                                #
#            "title": self.title,                                              #
#            "description": self.description,                                  #
#            "impact": self.impact,                                            #
#            "mitigation": self.mitigation,                                    #
#            "replication_steps": self.replication_steps,                      #
#            "host_detection_techniques": self.host_detection_techniques,      #
#            "network_detection_techniques": self.network_detection_techniques,#
#            "references": self.references,                                    #
#            "finding_guidance": self.finding_guidance,                        #
#            "tags": self.tags,                                                #
#            "extra_fields": self.extra_fields,                                #
#        }                                                                     #
################################################################################

    common_score_final_total = 0
    common_score_running_total = 0
    common_score_count = 0
    explicitly_weighted_fields = {"title", "finding_type", "description", "impact", "mitigation"}
    for field in fields(Finding):
        common_score = 0
        if field.name == "id" or field.name in explicitly_weighted_fields:
            # IDs are not semantic matches, and primary fields are already
            # scored above with their own configured weights.
            continue

        left_value = getattr(finding_left, field.name)
        right_value = getattr(finding_right, field.name)
        if field.name == "extra_fields":
            # Synchronisation timestamps are transport metadata, not finding
            # content, so they must not influence candidate selection.
            left_value = extra_fields_for_comparison(left_value)
            right_value = extra_fields_for_comparison(right_value)
        if isinstance(left_value, str) or isinstance(right_value, str):
            # Free-text common fields should benefit from the same comparison-only
            # punctuation and whitespace cleanup as the primary weighted fields.
            common_score_no_weight = fuzz.token_set_ratio(
                normalise_text_for_matching(left_value),
                normalise_text_for_matching(right_value),
            )
        elif left_value == right_value:
            # Otherwise, exact equality is the only safe comparison.
            common_score_no_weight = 100.0
        else:
            common_score_no_weight = 0.0

        common_score = common_score_no_weight * weights['common']
        common_score_count += 1
        log("DEBUG", f"Common field ({field.name}) weighted score between Finding Left and Right: {common_score:.2f}",
            prefix="MATCHING")

        common_score_running_total = common_score_running_total + common_score

    if common_score_count > 0:
        common_score_final_total = common_score_running_total / common_score_count


    # Calculate the weighted average of all component scores based on their configured importance
    combined_score = (title_score + type_score + desc_score + impact_score + mitigation_score + common_score_final_total)
    log("DEBUG", f"Final score: {combined_score:.2f}", prefix="MATCHING")

    return combined_score


def score_observation_similarity(observation_left: Observation, observation_right: Observation) -> float:
    """
    Computes a similarity score between two observations.

    Observations have a smaller schema than findings, so matching is deliberately
    title-led with description as supporting evidence.
    """
    log(
        "DEBUG",
        f"Scoring similarity between Observation Left (ID: {observation_left.id}) and "
        f"Observation Right (ID: {observation_right.id})",
        prefix="MATCHING",
    )
    title_weight = CONFIG.get("match_weight_title", 0.6)
    description_weight = CONFIG.get("match_weight_description", 0.4)
    total_weight = title_weight + description_weight
    if total_weight <= 0:
        title_weight = 0.6
        description_weight = 0.4
        total_weight = 1.0

    title_score_raw = fuzz.token_set_ratio(
        normalise_text_for_matching(observation_left.title),
        normalise_text_for_matching(observation_right.title),
    )
    if title_score_raw < CONFIG.get("match_min_threshold_title"):
        return title_score_raw * (title_weight / total_weight)

    description_score_raw = 0
    if observation_left.description and observation_right.description:
        description_score_raw = fuzz.token_set_ratio(
            normalise_text_for_matching(observation_left.description),
            normalise_text_for_matching(observation_right.description),
        )

    return (
        title_score_raw * (title_weight / total_weight)
        + description_score_raw * (description_weight / total_weight)
    )


def score_record_similarity(record_left: MergeRecord, record_right: MergeRecord) -> float:
    """Dispatch similarity scoring by reviewed template type."""
    if isinstance(record_left, Observation) and isinstance(record_right, Observation):
        return score_observation_similarity(record_left, record_right)
    return score_finding_similarity(record_left, record_right)

def fuzzy_match_findings(
    list_Left: List[Finding],
    list_Right: List[Finding],
    threshold: float
) -> Tuple[List[Dict[str,Finding|str]], List[Finding], List[Finding]]:
    """
    Matches findings from two lists using fuzzy scoring.

    Returns:
    - matches: Dict of tuples (Finding A, Finding B, score)
    - unmatched_left: findings in Left that were not matched by Right
    - unmatched_right: findings in Right that were not matched by Left
    """
    # Canonicalise both candidate sets before selecting or scoring any pair.
    _normalise_records_before_matching(list_Left, list_Right)

    log("INFO", f"Beginning fuzzy match on {len(list_Left)} findings from Left and {len(list_Right)} from Right", prefix="MATCHING")

    matches: List[Dict[str,Finding|float]] = []
    unmatched_left: List[Finding] = []
    matched_indices_right = set()

    for idx_left, finding_left in enumerate(list_Left):
        log("DEBUG", f"Searching match for Left #{idx_left} (ID: {finding_left.id})", prefix="MATCHING")
        best_match = None
        best_score = 0
        best_idx_right = -1

        for idx_right, finding_right in enumerate(list_Right):
            if idx_right in matched_indices_right:
                log("DEBUG", f"Skipping Right #{idx_right} (already matched)", prefix="MATCHING")
                continue

            score = score_finding_similarity(finding_left, finding_right)
            log("DEBUG", f"→ Fuzzy match score is: {score:.2f} (Left#{idx_left} Right#{idx_right})", prefix="MATCHING")

            # Update the best match candidate if this score is the highest so far
            # This ensures we only retain the top-scoring match per item in list A
            if score > best_score:
                # Store the highest score seen for this Left item
                best_score = score
                # Temporarily store this finding from Right as the best candidate
                best_match = finding_right
                # Remember this index so we can mark it as matched later
                best_idx_right = idx_right

        if best_score >= threshold and best_match:
            matches.extend([{"left": finding_left, "right": best_match, "score": best_score}])
            matched_indices_right.add(best_idx_right)
            log("INFO", f"Matched Left #{idx_left} (ID: {finding_left.id}) with Right #{best_idx_right} (ID: {best_match.id}) at {best_score:.2f}", prefix="MATCHING")
        else:
            unmatched_left.append(finding_left)
            log("DEBUG", f"No match found for Left#{idx_left} (best was {best_score:.2f})", prefix="MATCHING")

    unmatched_right = [right for idx, right in enumerate(list_Right) if idx not in matched_indices_right]

    log("INFO", f"Fuzzy matched {len(matches)} pairs", prefix="MATCHING")
    log("INFO", f"Unmatched: {len(unmatched_left)} in Left, {len(unmatched_right)} in Right", prefix="MATCHING")
    log("INFO", f"=== Fuzzing matching round complete ===", prefix="MATCHING")

    return matches, unmatched_left, unmatched_right


def fuzzy_match_records(
    list_left: List[MergeRecord],
    list_right: List[MergeRecord],
    threshold: float,
) -> Tuple[List[Dict[str, MergeRecord | str]], List[MergeRecord], List[MergeRecord]]:
    """
    Matches records from two lists using the scoring routine for their type.
    """
    # Findings and observations share the same recursive normalisation boundary.
    _normalise_records_before_matching(list_left, list_right)

    matches: List[Dict[str, MergeRecord | float]] = []
    unmatched_left: List[MergeRecord] = []
    matched_indices_right = set()

    for idx_left, record_left in enumerate(list_left):
        best_match = None
        best_score = 0
        best_idx_right = -1

        for idx_right, record_right in enumerate(list_right):
            if idx_right in matched_indices_right:
                continue

            score = score_record_similarity(record_left, record_right)
            if score > best_score:
                best_score = score
                best_match = record_right
                best_idx_right = idx_right

        if best_score >= threshold and best_match:
            matches.append({"left": record_left, "right": best_match, "score": best_score})
            matched_indices_right.add(best_idx_right)
        else:
            unmatched_left.append(record_left)

    unmatched_right = [right for idx, right in enumerate(list_right) if idx not in matched_indices_right]
    return matches, unmatched_left, unmatched_right
