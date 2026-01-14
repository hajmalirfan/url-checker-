function check() {
    const url = document.getElementById("url").value;
    fetch("/check?url=" + url)
    .then(r => r.json())
    .then(d => {
        document.getElementById("out").innerText =
        JSON.stringify(d, null, 2);
    });
}