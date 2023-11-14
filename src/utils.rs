use std::collections::HashSet;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

pub fn get_temp_filename() -> Result<String, SystemTimeError> {
    Ok(format!(
        "_shinobu_{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()
    ))
}

pub fn count_unique<T, F, R>(vec: &[T], lambda: F) -> usize
where
    F: Fn(&T) -> R,
    R: std::cmp::Eq + std::hash::Hash,
{
    vec.iter().map(lambda).collect::<HashSet<_>>().len()
}
