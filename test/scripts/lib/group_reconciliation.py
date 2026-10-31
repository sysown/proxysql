from collections import Counter, defaultdict
from dataclasses import dataclass


@dataclass(frozen=True)
class GroupReconciliation:
    passed: set[str]
    failed: set[str]
    skipped: set[str]
    missing: set[str]
    duplicates: set[str]

    @property
    def ok(self) -> bool:
        return (
            not self.failed
            and not self.skipped
            and not self.missing
            and not self.duplicates
        )


def reconcile_group_results(
    declared: set[str],
    discovered: list[str],
    results: list[tuple[str, int | None]],
) -> GroupReconciliation:
    """Reconcile one selected TAP group across all discovered workdirs."""
    selected_discovered = [name for name in discovered if name in declared]
    discovered_counts = Counter(selected_discovered)
    discovered_names = set(selected_discovered)

    duplicates = {
        name for name, count in discovered_counts.items() if count > 1
    }
    missing = declared - discovered_names

    statuses_by_name: dict[str, list[int | None]] = defaultdict(list)
    for name, status in results:
        if name in declared:
            statuses_by_name[name].append(status)

    passed: set[str] = set()
    failed: set[str] = set()
    skipped: set[str] = set()
    for name in discovered_names:
        statuses = statuses_by_name.get(name, [])
        if any(status is not None and status != 0 for status in statuses):
            failed.add(name)
        elif not statuses or any(status is None for status in statuses):
            skipped.add(name)
        else:
            passed.add(name)

    return GroupReconciliation(
        passed=passed,
        failed=failed,
        skipped=skipped,
        missing=missing,
        duplicates=duplicates,
    )
