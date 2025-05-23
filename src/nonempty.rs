// SPDX-License-Identifier: Apache-2.0 OR MIT

use serde::Deserialize;
use std::collections::BTreeSet;
use std::iter::FromIterator;
use std::ops::Deref;

/// Wrapper over BTreeSet that ensures it is not empty after deserialization.
#[derive(Debug, Clone, Ord, Eq, PartialOrd, PartialEq)]
pub(crate) struct NonEmptySet<T>(BTreeSet<T>);

impl<T> Default for NonEmptySet<T> {
    fn default() -> Self {
        NonEmptySet(BTreeSet::default())
    }
}

impl<'de, T> Deserialize<'de> for NonEmptySet<T>
where
    T: Deserialize<'de> + Ord,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let set = BTreeSet::<T>::deserialize(deserializer)?;
        if set.is_empty() {
            Err(serde::de::Error::invalid_length(0, &"at least one element"))
        } else {
            Ok(NonEmptySet(set))
        }
    }
}

impl<T> Deref for NonEmptySet<T> {
    type Target = BTreeSet<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> IntoIterator for NonEmptySet<T> {
    type Item = T;
    type IntoIter = <BTreeSet<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> FromIterator<T> for NonEmptySet<T>
where
    T: Ord,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

pub(crate) trait NonEmptyStructInner {
    const ERROR_MESSAGE: &'static str;

    fn is_empty(&self) -> bool;
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NonEmptyStruct<T>(T)
where
    T: NonEmptyStructInner;

impl<T> NonEmptyStruct<T>
where
    T: NonEmptyStructInner,
{
    pub(crate) fn into_inner(self) -> T {
        self.0
    }

    pub(crate) fn convert<U>(self) -> NonEmptyStruct<U>
    where
        U: NonEmptyStructInner + From<T>,
    {
        NonEmptyStruct(U::from(self.0))
    }
}

impl<'de, T> Deserialize<'de> for NonEmptyStruct<T>
where
    T: Deserialize<'de> + NonEmptyStructInner,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let src = T::deserialize(deserializer)?;
        if src.is_empty() {
            Err(serde::de::Error::custom(T::ERROR_MESSAGE))
        } else {
            Ok(NonEmptyStruct(src))
        }
    }
}
