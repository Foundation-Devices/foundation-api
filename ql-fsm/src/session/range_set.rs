use std::{
    cmp,
    collections::BTreeMap,
    ops::{
        Bound::{Excluded, Included},
        Range,
    },
};

/// A set of `u64` values optimized for long runs and random insert/delete.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RangeSet(BTreeMap<u64, u64>);

impl RangeSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, mut x: Range<u64>) -> bool {
        if x.is_empty() {
            return false;
        }

        if let Some((start, end)) = self.before(x.start) {
            if end >= x.end {
                return false;
            } else if end >= x.start {
                self.0.remove(&start);
                x.start = start;
            }
        }

        while let Some((next_start, next_end)) = self.after(x.start) {
            if next_start > x.end {
                break;
            }
            self.0.remove(&next_start);
            x.end = cmp::max(next_end, x.end);
        }

        self.0.insert(x.start, x.end);
        true
    }

    pub fn remove(&mut self, x: Range<u64>) -> bool {
        if x.is_empty() {
            return false;
        }

        let before = match self.before(x.start) {
            Some((start, end)) if end > x.start => {
                self.0.remove(&start);
                if start < x.start {
                    self.0.insert(start, x.start);
                }
                if end > x.end {
                    self.0.insert(x.end, end);
                }
                if end >= x.end {
                    return true;
                }
                true
            }
            Some(_) | None => false,
        };

        let mut after = false;
        while let Some((start, end)) = self.after(x.start) {
            if start >= x.end {
                break;
            }
            after = true;
            self.0.remove(&start);
            if end > x.end {
                self.0.insert(x.end, end);
                break;
            }
        }

        before || after
    }

    pub fn min(&self) -> Option<u64> {
        self.0.first_key_value().map(|(&start, _)| start)
    }

    pub fn max(&self) -> Option<u64> {
        self.0
            .last_key_value()
            .map(|(_, &end)| end.checked_sub(1).unwrap())
    }

    pub fn contains(&self, x: u64) -> bool {
        self.before(x).is_some_and(|(_, end)| end > x)
    }

    pub fn range_count(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> Iter<'_> {
        Iter(self.0.iter())
    }

    pub fn iter_rev(&self) -> RevIter<'_> {
        RevIter(self.0.iter().rev())
    }

    pub fn peek_min(&self) -> Option<Range<u64>> {
        let (&start, &end) = self.0.iter().next()?;
        Some(start..end)
    }

    pub fn pop_min(&mut self) -> Option<Range<u64>> {
        let result = self.peek_min()?;
        self.0.remove(&result.start);
        Some(result)
    }

    #[cfg(test)]
    pub fn peek_max(&self) -> Option<Range<u64>> {
        let (&start, &end) = self.0.iter().next_back()?;
        Some(start..end)
    }

    #[cfg(test)]
    pub fn pop_max(&mut self) -> Option<Range<u64>> {
        let result = self.peek_max()?;
        self.0.remove(&result.start);
        Some(result)
    }

    /// find closest range to `x` that begins at or before it
    fn before(&self, x: u64) -> Option<(u64, u64)> {
        self.0
            .range((Included(0), Included(x)))
            .next_back()
            .map(|(&start, &end)| (start, end))
    }

    /// find the closest range to `x` that begins after it
    fn after(&self, x: u64) -> Option<(u64, u64)> {
        self.0
            .range((Excluded(x), Included(u64::MAX)))
            .next()
            .map(|(&start, &end)| (start, end))
    }
}

pub struct Iter<'a>(std::collections::btree_map::Iter<'a, u64, u64>);

impl Iterator for Iter<'_> {
    type Item = Range<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(&start, &end)| start..end)
    }
}

pub struct RevIter<'a>(std::iter::Rev<std::collections::btree_map::Iter<'a, u64, u64>>);

impl Iterator for RevIter<'_> {
    type Item = Range<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(&start, &end)| start..end)
    }
}

#[cfg(test)]
mod tests {
    use super::RangeSet;

    #[test]
    fn insert_merges_overlaps() {
        let mut set = RangeSet::new();
        assert!(set.insert(10..20));
        assert!(set.insert(30..40));
        assert!(set.insert(15..35));
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![10..40]);
    }

    #[test]
    fn remove_splits_ranges() {
        let mut set = RangeSet::new();
        set.insert(10..40);
        assert!(set.remove(20..30));
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![10..20, 30..40]);
    }

    #[test]
    fn reverse_iteration_visits_highest_range_first() {
        let mut set = RangeSet::new();
        set.insert(10..20);
        set.insert(30..40);
        set.insert(50..60);

        assert_eq!(
            set.iter_rev().collect::<Vec<_>>(),
            vec![50..60, 30..40, 10..20]
        );
        assert_eq!(set.peek_max(), Some(50..60));
        assert_eq!(set.pop_max(), Some(50..60));
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![10..20, 30..40]);
    }

    #[test]
    fn contains_and_max_reflect_current_membership() {
        let mut set = RangeSet::new();
        set.insert(10..20);
        set.insert(30..31);

        assert!(!set.contains(9));
        assert!(set.contains(10));
        assert!(set.contains(19));
        assert!(!set.contains(20));
        assert_eq!(set.min(), Some(10));
        assert_eq!(set.max(), Some(30));
        assert_eq!(set.range_count(), 2);
    }
}
