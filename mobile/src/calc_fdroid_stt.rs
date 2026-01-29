use crate::models::FDroidApp;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub enum FDroidFetchStatus {
    Pending,
    Fetching,
    Success(FDroidApp),
    Error(String),
}

pub struct FDroidQueue {
    pub queue: Arc<Mutex<VecDeque<String>>>,
    pub results: Arc<Mutex<HashMap<String, FDroidFetchStatus>>>,
    pub is_running: Arc<Mutex<bool>>,
}
