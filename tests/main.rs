use multisig_ecdsa::config::Settings;
use multisig_ecdsa::startup::api_doc::{PostMsgRequest, SignMsgRequest};
use multisig_ecdsa::startup::Application;
use reqwest::StatusCode;

type MsgId = String;

pub struct TestApp {
    pub address: String,
    pub port: u16,
    pub config: Settings,
}

impl TestApp {
    pub async fn spawn_app() -> TestApp {
        let mut config = Settings::load_configuration()
            .expect("failed to load configuration");
        config.app_port = 0;

        let application = Application::build(config.clone())
            .await
            .expect("failed to build application");

        let port = application.port();
        let address = format!("http://{}:{}", config.app_ip, port);

        tokio::spawn(application.run_until_stopped());

        TestApp {
            address,
            port,
            config,
        }
    }
    async fn create_user_with_keys(
        &self,
        c: &reqwest::Client,
    ) -> Result<Vec<String>, reqwest::Error> {
        // Create a user
        let create_user_resp = c
            .post(format!("{}/api/v1/user?name=testuser", self.address))
            .send()
            .await?;
        assert_eq!(create_user_resp.status(), StatusCode::OK);

        // Generate keypairs for the user
        let mut keys = Vec::with_capacity(3);
        for _ in 0..3 {
            let bt_addr_resp = c
                .post(format!("{}/api/v1/user/testuser/keypair", self.address))
                .send()
                .await?;
            assert_eq!(bt_addr_resp.status(), StatusCode::OK);
            keys.push(bt_addr_resp.text().await?);
        }
        Ok(keys)
    }
    async fn create_msg(
        &self,
        c: &reqwest::Client,
        keys: &[String],
        msg: &str,
    ) -> Result<MsgId, reqwest::Error> {
        let create_msg_resp = c
            .post(format!("{}/api/v1/msg", self.address))
            .json(&PostMsgRequest {
                content: msg.to_string(),
                keys: keys.to_vec(),
                required_signature_count: None,
            })
            .send()
            .await?;
        assert_eq!(create_msg_resp.status(), StatusCode::OK);
        let msg_id = create_msg_resp.text().await?;
        Ok(msg_id)
    }
}

#[tokio::test]
async fn test_create_and_verify_message(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = TestApp::spawn_app().await;
    let addr = &app.address;
    let client = reqwest::Client::new();

    // Create user & keys
    let keys = app.create_user_with_keys(&client).await?;

    // Create a message
    let msg_id = app.create_msg(&client, &keys, "Hello world!").await?;

    // Sign the message
    let sign_msg_resp = client
        .post(format!("{}/api/v1/msg/{}", addr, msg_id))
        .json(&SignMsgRequest { keys })
        .send()
        .await?;
    assert_eq!(sign_msg_resp.status(), StatusCode::OK);

    // Verify the message signature
    let verify_msg_resp = client
        .get(format!("{}/api/v1/msg/{}", addr, msg_id))
        .send()
        .await?;
    assert_eq!(verify_msg_resp.status(), StatusCode::OK);
    assert_eq!(verify_msg_resp.text().await?, "success");

    Ok(())
}

#[tokio::test]
async fn test_bad_key_fail() -> Result<(), Box<dyn std::error::Error>> {
    let app = TestApp::spawn_app().await;
    let addr = &app.address;
    let client = reqwest::Client::new();

    // Try create a message
    let response = client
        .post(format!("{}/api/v1/msg", addr))
        .json(&PostMsgRequest {
            content: "Hello world!".to_string(),
            keys: vec!["badkey".to_string()],
            required_signature_count: None,
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}
