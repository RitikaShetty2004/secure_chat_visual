function sendMessage() {
    const msgInput = document.getElementById("msg");
    const msg = msgInput.value.trim();

    if (msg === "") {
        alert("Please type a message before sending.");
        return;
    }

    // Send the message using a POST request and navigate
    fetch("/process_message", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ msg: msg })
    })
    .then(response => {
        if (response.redirected) {
            window.location.href = response.url;
        } else {
            return response.json().then(data => {
                alert(data.error || "Something went wrong.");
            });
        }
    });
}
