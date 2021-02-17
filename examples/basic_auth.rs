#![deny(warnings)]

use headers::authorization::Basic;
use warp::auth::{basic, Authorizer};
use warp::Filter;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

struct Auth {
    users: Arc<RwLock<HashMap<&'static str, &'static str>>>,
}

impl Authorizer for Auth {
    fn basic(&self, basic: &Basic) -> Result<(), ()> {
        let lock = self.users.read().map_err(|_e| {
            println!("Locked RwLock from same thread twice....");
        })?;
        if let Some(pw) = lock.get(basic.username()) {
            if *pw == basic.password() {
                return Ok(());
            }
        }
        Err(())
    }
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
        .with(basic("MyRealm", auth));

    // GET / => README.md
    // GET /ex/... => ./examples/..
    let routes = readme.or(secret_examples);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
