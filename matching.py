# external module imports
from imports import (fuzz, Dict, List, Tuple)
# get global state objects (CONFIG and TUI)
from globals import get_config
CONFIG = get_config()
# local module imports
from utils import log, normalise_tags
from model import Finding

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
        "title": CONFIG.get("match_weight_title", 0.3),
        "type": CONFIG.get("match_weight_finding_type", 0.1),
        "desc": CONFIG.get("match_weight_description", 0.2),
        "impact": CONFIG.get("match_weight_impact", 0.2),
        "mitigation": CONFIG.get("match_weight_mitigation", 0.2),
    }
    log("DEBUG", f"Raw weights: title={raw_weights['title']:.2f}, type={raw_weights['type']:.2f}, desc={raw_weights['desc']:.2f}, impact={raw_weights['impact']:.2f}, mitigation={raw_weights['mitigation']:.2f}", prefix="MATCHING")

    # balances the weights, if they add up to more than 1
    total_weights = sum(raw_weights.values())
    weights = total_weights
    if total_weights > 1:
        normalised_weights = {k: v/total_weights for k, v in raw_weights.items()}
        weights = normalised_weights

    log("DEBUG", f"Normalised weights: title={weights['title']:.2f}, type={weights['type']:.2f}, desc={weights['desc']:.2f}, impact={weights['impact']:.2f}, mitigation={weights['mitigation']:.2f}",prefix="MATCHING")

    # Title similarity using token sort ratio (handles reordering well)
    title_score_no_weight = fuzz.token_set_ratio(finding_left.title, finding_right.title)
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
        desc_score_no_weight = fuzz.token_set_ratio(finding_left.description, finding_right.description)
        desc_score = desc_score_no_weight * weights['desc']
        log("DEBUG", f"Description weighted score between Finding Left and Right: {desc_score:.2f}", prefix="MATCHING")
    else:
        log("DEBUG", "At least one finding is missing an impact. Description score is 0", prefix="MATCHING")

    # Impact similarity scoring
    impact_score = 0
    if finding_left.impact and finding_right.impact:
        impact_score_no_weight = fuzz.token_set_ratio(finding_left.impact, finding_right.impact)
        impact_score = impact_score_no_weight * weights['impact']
        log("DEBUG", f"Impact weighted score between Finding Left and Right: {impact_score:.2f}", prefix="MATCHING")
    else:
        log("DEBUG", "At least one finding is missing an impact. Impact score is 0", prefix="MATCHING")

    # Mitigation similarity scoring
    mitigation_score = 0
    if finding_left.mitigation and finding_right.mitigation:
        mitigation_score_no_weight = fuzz.token_set_ratio(finding_left.mitigation, finding_right.mitigation)
        mitigation_score = mitigation_score_no_weight * weights['mitigation']
        log("DEBUG", f"Mitigation weighted score between Finding Left and Right: {mitigation_score:.2f}", prefix="MATCHING")
    else:
        log("DEBUG", "At least one finding is missing a mitigation. Mitigation score is 0", prefix="MATCHING")

    # Calculate the weighted average of all component scores based on their configured importance
    combined_score = (title_score + type_score + desc_score + impact_score + mitigation_score)
    log("DEBUG", f"Final score: {combined_score:.2f}", prefix="MATCHING")

    return combined_score

def fuzzy_match_findings(
    list_Left: List[Finding],
    list_Right: List[Finding],
    threshold: float,
    next_id: int
) -> Tuple[List[Dict[str,Finding|str]], List[Finding], List[Finding]]:
    """
    Matches findings from two lists using fuzzy scoring.

    Returns:
    - matches: Dict of tuples (Finding A, Finding B, score)
    - unmatched_left: findings in Left that were not matched by Right
    - unmatched_right: findings in Right that were not matched by Left
    """
    log("INFO", f"Beginning fuzzy match on {len(list_Left)} findings from Left and {len(list_Right)} from Right", prefix="MATCHING")

    matches: List[Dict[str,Finding|float]] = []
    unmatched_left: List[Finding] = []
    matched_indices_right = set()

    for idx_left, finding_left in enumerate(list_Left):
        log("DEBUG", f"Searching match for Left#{idx_left} (ID: {finding_left.id})", prefix="MATCHING")
        best_match = None
        best_score = 0
        best_idx_right = -1

        for idx_right, finding_right in enumerate(list_Right):
            if idx_right in matched_indices_right:
                log("DEBUG", f"Skipping Right#{idx_right} (already matched)", prefix="MATCHING")
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
            log("INFO", f"Matched Left#{idx_left} (ID: {finding_left.id}) with Right#{best_idx_right} (ID: {best_match.id}) at {best_score:.2f}", prefix="MATCHING")
        else:
            unmatched_left.append(finding_left)
            log("DEBUG", f"No match found for Left#{idx_left} (best was {best_score:.2f})", prefix="MATCHING")

    unmatched_right = [right for idx, right in enumerate(list_Right) if idx not in matched_indices_right]

    log("INFO", f"Fuzzy matched {len(matches)} pairs", prefix="MATCHING")
    log("INFO", f"Unmatched: {len(unmatched_left)} in Left, {len(unmatched_right)} in Right", prefix="MATCHING")
    log("INFO", f"=== Fuzzing matching round complete ===", prefix="MATCHING")

    return matches, unmatched_left, unmatched_right
