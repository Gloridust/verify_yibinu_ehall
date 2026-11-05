//! 只读联调：加载登录页、检查是否需要验证码、获取验证码图片。不提交任何凭据。
//! cargo run --example live_probe
fn main() -> Result<(), yibinu_auth::AuthError> {
    let c = yibinu_auth::Client::new(Default::default())?;
    let page = c.load_login_page()?;
    println!("captcha_switch = {}", page.captcha_switch);
    println!("password form  = {}", page.password_form.is_some());
    println!("sms form       = {}", page.sms_form.is_some());
    println!(
        "need_captcha   = {}",
        c.need_captcha("zz_nonexistent_0001")?
    );
    println!("captcha bytes  = {}", c.fetch_captcha()?.len());
    Ok(())
}
