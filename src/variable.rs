// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::parser::{TemplateString, TemplateToken};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    iter::Peekable,
    str::FromStr,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Name {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(NameError::Empty);
        }

        if !s.chars().next().unwrap().is_ascii_alphabetic() {
            return Err(NameError::InvalidFirstCharacter(s.to_string()));
        }

        if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(NameError::InvalidCharacter(s.to_string()));
        }

        Ok(Self(s.to_string()))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NameError {
    #[error("name cannot be empty")]
    Empty,
    #[error("invalid first character in name (must be ASCII alphabetic): {0}")]
    InvalidFirstCharacter(String),
    #[error("invalid character(s) in name (must be ASCII alphanumeric or '_'): {0}")]
    InvalidCharacter(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Variables(BTreeMap<Name, BTreeSet<String>>);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error("variable '{0}' not found")]
    VariableNotFound(Name),
    #[error(transparent)]
    InvalidName(#[from] NameError),
}

impl Variables {
    pub(crate) fn extend(&mut self, key: Name, values: BTreeSet<String>) {
        self.0.entry(key).or_default().extend(values);
    }

    // TODO: Return references instead of cloning.
    pub(crate) fn resolve(
        &self,
        template: &TemplateString,
    ) -> Result<Vec<BTreeSet<String>>, ResolveError> {
        template
            .0
            .iter()
            .map(|token| match token {
                TemplateToken::Text(text) => Ok([text.to_string()].into()),
                TemplateToken::Var(name) => self
                    .0
                    .get(name)
                    .cloned()
                    .ok_or_else(|| ResolveError::VariableNotFound(name.clone())),
            })
            .collect()
    }

    pub(crate) fn iter(&self) -> std::collections::btree_map::Iter<'_, Name, BTreeSet<String>> {
        self.0.iter()
    }

    // Used by tests_parser.rs
    #[allow(dead_code)]
    pub(crate) fn try_from<K, V, S, I>(list: I) -> Result<Self, NameError>
    where
        K: AsRef<str>,
        V: IntoIterator<Item = S>,
        S: AsRef<str>,
        I: IntoIterator<Item = (K, V)>,
    {
        let mut map = BTreeMap::new();
        for (key, values) in list {
            let name = Name::from_str(key.as_ref())?;
            map.insert(
                name,
                values
                    .into_iter()
                    .map(|s| s.as_ref().to_string())
                    .collect::<BTreeSet<_>>(),
            );
        }
        Ok(Self(map))
    }
}

struct SetIterReset<'a, T>
where
    T: 'a,
{
    set: &'a BTreeSet<T>,
    iter: Peekable<std::collections::btree_set::Iter<'a, T>>,
}

impl<'a, T> SetIterReset<'a, T>
where
    T: 'a,
{
    fn new(set: &'a BTreeSet<T>) -> Self {
        Self {
            set,
            iter: set.iter().peekable(),
        }
    }

    fn reset(&mut self) {
        self.iter = self.set.iter().peekable();
    }
}

pub(crate) struct VecStringIterator<'a, T> {
    vec: Vec<SetIterReset<'a, T>>,
    is_final: bool,
}

impl<'a, T> VecStringIterator<'a, T> {
    pub(crate) fn new(vec: &'a [BTreeSet<T>]) -> Self {
        Self {
            vec: vec
                .iter()
                .map(|set| SetIterReset::new(set))
                .collect::<Vec<_>>(),
            is_final: false,
        }
    }
}

/// Iterator that generates the Cartesian product of multiple sets, producing
/// all possible combinations as concatenated strings in lexicographic order.
impl<'a, T> Iterator for VecStringIterator<'a, T>
where
    T: AsRef<str> + 'a,
{
    // TODO: Use PathBuf, canonicalize, and filter to avoid consecutive returned paths to be the
    // same (e.g. peekable + dedup).
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_final {
            return None;
        }

        let mut ret = vec![];
        let mut carry = true;
        for set in self.vec.iter_mut().rev() {
            if let Some(value) = set.iter.peek() {
                ret.push((*value).as_ref());
            } else {
                return None;
            }
            if carry {
                set.iter.next();
                if set.iter.peek().is_some() {
                    carry = false;
                } else {
                    set.reset();
                }
            }
        }

        if carry {
            self.is_final = true;
            if ret.is_empty() {
                return None;
            }
        }

        ret.reverse();
        Some(ret.join(""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vec_string_iterator_empty_vec() {
        let vec: Vec<BTreeSet<String>> = vec![];
        let mut iter = VecStringIterator::new(&vec);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_vec_string_iterator_single_empty_set() {
        let set = BTreeSet::<String>::new();
        let vec = vec![set];
        let mut iter = VecStringIterator::new(&vec);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_vec_string_iterator_one_set() {
        // BTreeSet are automatically sorted, so we should not rely on this order.
        let set: BTreeSet<_> = ["b", "a"].into();
        let vec = vec![set];
        let mut iter = VecStringIterator::new(&vec);

        assert_eq!(iter.next(), Some("a".to_string()));
        assert_eq!(iter.next(), Some("b".to_string()));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_vec_string_iterator_two_sets() {
        let set1: BTreeSet<_> = ["a", "b"].into();
        let set2: BTreeSet<_> = ["2", "1", "3"].into();
        let vec = vec![set1, set2];
        let iter = VecStringIterator::new(&vec);

        // Collect all results and sort for comparison
        let results: Vec<String> = iter.collect();

        // Cartesian product of the sets.
        let expected = ["a1", "a2", "a3", "b1", "b2", "b3"].map(|s| s.to_string());
        assert_eq!(results, expected);
    }

    #[test]
    fn test_vec_string_iterator_three_sets() {
        let set1: BTreeSet<_> = ["a", "b"].into();
        let set2: BTreeSet<_> = ["2", "1", "3"].into();
        let set3: BTreeSet<_> = ["Y", "X"].into();
        let vec = vec![set1, set2, set3];
        let iter = VecStringIterator::new(&vec);

        // Collect all results and sort for comparison
        let results: Vec<String> = iter.collect();

        // Cartesian product of the sets.
        let expected = [
            "a1X", "a1Y", "a2X", "a2Y", "a3X", "a3Y", "b1X", "b1Y", "b2X", "b2Y", "b3X", "b3Y",
        ]
        .map(|s| s.to_string());
        assert_eq!(results, expected);
    }

    #[test]
    fn test_vec_string_iterator_with_empty_set() {
        let set1: BTreeSet<_> = ["a"].into();
        let set2 = BTreeSet::new();
        let set3: BTreeSet<_> = ["Y"].into();

        let vec = vec![set1, set2, set3];
        let mut iter = VecStringIterator::new(&vec);

        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }
}
