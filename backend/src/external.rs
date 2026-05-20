use anyhow::Context;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct ExternalClient {
    base: String,
    http: Client,
}

#[derive(Serialize)]
struct RegisterBody<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
struct RegisterResp {
    #[allow(dead_code)]
    uuid: String,
}

#[derive(Serialize)]
struct LoginBody<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
struct LoginResp {
    access_token: String,
}

#[derive(Serialize)]
struct PostJobBody<'a> {
    job_type: &'a str,
}

#[derive(Deserialize)]
struct PostJobResp {
    job_id: String,
}

impl ExternalClient {
    pub fn new(base: String, http: Client) -> Self {
        Self { base, http }
    }

    pub async fn register(&self, username: &str, password: &str) -> anyhow::Result<()> {
        let res = self
            .http
            .post(format!("{}/api/auth/register", self.base))
            .json(&RegisterBody { username, password })
            .send()
            .await?;
        if !res.status().is_success() {
            anyhow::bail!("register failed ({}): {}", res.status(), res.text().await?);
        }
        let _: RegisterResp = res.json().await?;
        Ok(())
    }

    pub async fn login(&self, username: &str, password: &str) -> anyhow::Result<String> {
        let res = self
            .http
            .post(format!("{}/api/auth/login", self.base))
            .json(&LoginBody { username, password })
            .send()
            .await?;
        if !res.status().is_success() {
            anyhow::bail!("login failed ({}): {}", res.status(), res.text().await?);
        }
        let body: LoginResp = res.json().await?;
        Ok(body.access_token)
    }

    pub async fn upload_server_key(&self, jwt: &str, key_bytes: Vec<u8>) -> anyhow::Result<()> {
        let res = self
            .http
            .post(format!("{}/api/user/server-key", self.base))
            .bearer_auth(jwt)
            .header("content-type", "application/octet-stream")
            .body(key_bytes)
            .send()
            .await?;
        if !res.status().is_success() {
            anyhow::bail!("server-key upload failed: {}", res.text().await?);
        }
        Ok(())
    }

    pub async fn post_job(&self, jwt: &str, job_type: &str) -> anyhow::Result<Uuid> {
        let res = self
            .http
            .post(format!("{}/api/job/post", self.base))
            .bearer_auth(jwt)
            .json(&PostJobBody { job_type })
            .send()
            .await?;
        if !res.status().is_success() {
            anyhow::bail!("post_job failed: {}", res.text().await?);
        }
        let body: PostJobResp = res.json().await?;
        body.job_id.parse().context("invalid job_id from external service")
    }

    pub async fn upload_job_data(
        &self,
        jwt: &str,
        job_id: Uuid,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        let res = self
            .http
            .post(format!("{}/api/job/{job_id}/data", self.base))
            .bearer_auth(jwt)
            .header("content-type", "application/octet-stream")
            .body(data)
            .send()
            .await?;
        if !res.status().is_success() {
            anyhow::bail!("upload_job_data failed: {}", res.text().await?);
        }
        Ok(())
    }

    /// Returns `None` when the job is not yet finished (HTTP 500 per openapi spec).
    pub async fn get_job_result(&self, jwt: &str, job_id: Uuid) -> anyhow::Result<Option<Vec<u8>>> {
        let res = self
            .http
            .get(format!("{}/api/job/{job_id}", self.base))
            .bearer_auth(jwt)
            .send()
            .await?;
        match res.status().as_u16() {
            200 => Ok(Some(res.bytes().await?.to_vec())),
            500 => Ok(None), // "Job not found or not yet finished"
            code => anyhow::bail!(
                "get_job_result unexpected status {code}: {}",
                res.text().await?
            ),
        }
    }
}
