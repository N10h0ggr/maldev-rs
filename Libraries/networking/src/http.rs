use reqwest;

/// Sends a synchronous HTTP GET request to the specified URL and retrieves the response body as a string.
///
/// # Arguments
///
/// * `url` - A string slice representing the URL to which the GET request will be sent.
///
/// # Returns
///
/// * `Result<String, String>` - If successful, returns `Ok` containing the response body as a string.
///   If an error occurs during the request or response handling, returns `Err` containing an error message.
///
/// # Examples
///
/// ```rust
/// use crate::fetch_data;
///
/// match fetch_data("https://api.example.com/data") {
///     Ok(body) => println!("Received data: {}", body),
///     Err(err) => eprintln!("Error: {}", err),
/// }
/// ```
pub async fn fetch_shellcode(url: &str) -> Result<Vec<u8>, reqwest::Error> {
    let body = reqwest::get(url).await?.bytes().await?;
    Ok(Vec::from(body))
}