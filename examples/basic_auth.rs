#![deny(warnings)]

use warp::auth::{basic, AuthHeader};
use warp::Filter;
use tokio::sync::RwLock;
use std::{
    collections::HashMap,
    sync::Arc,
};

#[derive(Clone)]
struct Auth {
    users: Arc<RwLock<HashMap<&'static str, &'static str>>>,
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    let mut users = HashMap::new();
    users.insert("PersonOne", "CorrectHorseBatteryStaple");
    users.insert("PersonTwo", "Hunter2");
    let users = Arc::new(RwLock::new(users));
    let auth = Auth { users };
    let readme = warp::any()
        .and(warp::path::end())
        .and(warp::fs::file("./README.md"));

    // These files will only be available with a valid auth header
    let secret_examples = warp::path("ex")
        .and(warp::fs::dir("./examples/"))
        .with(basic("MyRealm", move |header| async move {
            if let AuthHeader::Basic(basic) = header {
                if let Some(pw) = user.lock().await.get(basic.username()) {
                    if pw == basic.password() {
                        return Ok(())
                    }
                }
            }
            Err(warp::reject::forbidden())
        }));

    // GET / => README.md
    // GET /ex/... => ./examples/..
    let routes = readme.or(secret_examples);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
