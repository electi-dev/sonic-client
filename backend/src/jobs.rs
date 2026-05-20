use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct JobEntry {
    pub username: String,
    pub external_job_id: Uuid,
    pub kind: JobKind,
    pub status: JobStatus,
}

#[derive(Clone, Debug)]
pub enum JobKind {
    Usecase1 { ip_count: usize },
    Usecase2,
}

#[derive(Clone, Debug)]
pub enum JobStatus {
    Pending,
    /// Decrypt task is running in the background.
    Processing,
    Done(JobResult),
    Error(String),
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", content = "data")]
pub enum JobResult {
    Usecase1(Vec<IpResult>),
    Usecase2(bool),
}

#[derive(Clone, Debug, Serialize)]
pub struct IpResult {
    pub ip: String,
    pub matched: bool,
}

#[derive(Serialize)]
pub struct JobStatusResponse {
    pub job_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<JobResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn to_response(
    job_id: Uuid,
    status: &str,
    result: Option<JobResult>,
    error: Option<String>,
) -> JobStatusResponse {
    JobStatusResponse {
        job_id: job_id.to_string(),
        status: status.to_string(),
        result,
        error,
    }
}
