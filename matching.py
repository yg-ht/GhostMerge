from common import (fuzz, List, Tuple, CONFIG, log, Finding)

def score_finding_similarity(f1: Finding, f2: Finding) -> float:
    """
    Computes a similarity score between two findings.
    Title match is weighted heavily, with optional fallback to description.
    Returns a float between 0.0 and 100.0.
    """
    log("DEBUG", f"Scoring similarity between Finding A (ID: {f1.id}) and Finding B (ID: {f2.id})", prefix="MATCHING")

    # Title similarity using token sort ratio (handles reordering well)
    title_score = fuzz.token_sort_ratio(f1.title or "", f2.title or "")
    log("DEBUG", f"Title score between '{f1.title}' and '{f2.title}': {title_score}", prefix="MATCHING")

    # Optional: description similarity fallback
    desc_score = 0
    if f1.description and f2.description:
        desc_score = fuzz.partial_ratio(f1.description, f2.description)
        log("DEBUG", f"Description score between Finding A and B: {desc_score}", prefix="MATCHING")
    else:
        log("DEBUG", "At least one finding is missing a description. Skipping desc score.", prefix="MATCHING")

    # Optional: finding_type similarity (exact match bonus)
    type_score = 100 if f1.finding_type == f2.finding_type and f1.finding_type else 0
    if f1.finding_type and f2.finding_type:
        log("DEBUG", f"Finding types: A='{f1.finding_type}' B='{f2.finding_type}' → Type score: {type_score}", prefix="MATCHING")
    else:
        log("DEBUG", "At least one finding is missing a finding_type. Skipping type score.", prefix="MATCHING")

    # Retrieve configurable weightings for each component from the loaded config
    # These determine how much influence title, description, and finding_type have on the final score
    title_weight = CONFIG.get("match_weight_title", 0.6)
    desc_weight = CONFIG.get("match_weight_description", 0.3)
    type_weight = CONFIG.get("match_weight_finding_type", 0.1)

    # Calculate the weighted average of all component scores based on their configured importance
    combined_score = (title_weight * title_score + desc_weight * desc_score + type_weight * type_score)
    log("DEBUG", f"[Weights: title={title_weight}, desc={desc_weight}, type={type_weight}] → Final score: {combined_score:.2f}", prefix="MATCHING")  # Logs the breakdown of the computed score with applied weights

    return combined_score

def fuzzy_match_findings(
    list_a: List[Finding],
    list_b: List[Finding],
    threshold: float = 85.0
) -> Tuple[List[Tuple[Finding, Finding, float]], List[Finding], List[Finding]]:
    """
    Matches findings from two lists using fuzzy scoring.

    Returns:
    - matches: list of tuples (Finding A, Finding B, score)
    - unmatched_a: findings in A that had no acceptable match
    - unmatched_b: findings in B that were not matched by A
    """
    log("INFO", f"Beginning fuzzy match on {len(list_a)} findings from A and {len(list_b)} from B", prefix="MATCHING")

    matches = []
    unmatched_a = []
    matched_indices_b = set()

    for idx_a, finding_a in enumerate(list_a):
        log("DEBUG", f"Searching match for A#{idx_a} (ID: {finding_a.id})", prefix="MATCHING")
        best_match = None
        best_score = 0
        best_idx_b = -1

        for idx_b, finding_b in enumerate(list_b):
            if idx_b in matched_indices_b:
                log("DEBUG", f"Skipping B#{idx_b} (already matched)", prefix="MATCHING")
                continue

            score = score_finding_similarity(finding_a, finding_b)
            log("DEBUG", f"→ Score A#{idx_a} ↔ B#{idx_b}: {score:.2f}", prefix="MATCHING")

            # Update the best match candidate if this score is the highest so far
            # This ensures we only retain the top-scoring match per item in list A
            if score > best_score:
                                # Store the highest score seen for this A item
                best_score = score
                                # Temporarily store this finding from B as the best candidate
                best_match = finding_b
                                # Remember this index so we can mark it as matched later
                best_idx_b = idx_b

        if best_score >= threshold and best_match:
            matches.append((finding_a, best_match, best_score))
            matched_indices_b.add(best_idx_b)
            log("INFO", f"Matched A#{idx_a} (ID: {finding_a.id}) with B#{best_idx_b} (ID: {best_match.id}) at {best_score:.2f}", prefix="MATCHING")
        else:
            unmatched_a.append(finding_a)
            log("DEBUG", f"No match found for A#{idx_a} (best was {best_score:.2f})", prefix="MATCHING")

    unmatched_b = [b for idx, b in enumerate(list_b) if idx not in matched_indices_b]

    log("INFO", f"Fuzzy matched {len(matches)} pairs", prefix="MATCHING")
    log("INFO", f"Unmatched: {len(unmatched_a)} in A, {len(unmatched_b)} in B", prefix="MATCHING")

    return matches, unmatched_a, unmatched_b
