document.addEventListener("DOMContentLoaded", function () {
    fetch('/static/content.txt')
        .then(response => response.text())
        .then(binaryData => {
            const binaryContainer = document.createElement("div");
            binaryContainer.classList.add("binary-container");
            binaryContainer.innerText = binaryData;
            document.body.appendChild(binaryContainer);
        })
        .catch(error => console.error("Error loading binary text:", error));
});

document.addEventListener("DOMContentLoaded", function() {
    console.log("Cyber Security Scanner Loaded!");
});

function checkPhishing() {
    let url = document.getElementById("phishing-url").value;
    if (!url) {
        alert("Please enter a URL");
        return;
    }

    fetch('/check_url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `url=${encodeURIComponent(url)}`
    })
    .then(response => response.text())
    .then(data => document.getElementById("result").innerHTML = data)
    .catch(error => console.error("Error:", error));
}

function checkWhois() {
    let domain = document.getElementById("whois-url").value;
    if (!domain) {
        alert("Please enter a domain");
        return;
    }

    fetch('/check_whois', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `domain=${encodeURIComponent(domain)}`
    })
    .then(response => response.text())
    .then(data => document.getElementById("result").innerHTML = data)
    .catch(error => console.error("Error:", error));
}

function checkEmail() {
    let email = document.getElementById("email-input").value;
    if (!email) {
        alert("Please enter an email");
        return;
    }

    let formData = new FormData();
    formData.append("email_file", email);

    fetch('/check_email', {
        method: 'POST',
        body: formData
    })
    .then(response => response.text())
    .then(data => document.getElementById("result").innerHTML = data)
    .catch(error => console.error("Error:", error));
}

function checkIP() {
    let ip = document.getElementById("ip-address").value;
    if (!ip) {
        alert("Please enter an IP address");
        return;
    }

    fetch('/check_ip', { // You need to create this route in Flask
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `ip=${encodeURIComponent(ip)}`
    })
    .then(response => response.text())
    .then(data => document.getElementById("result").innerHTML = data)
    .catch(error => console.error("Error:", error));
}
