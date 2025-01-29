chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
      const flaskAPI = "http://127.0.0.1:5000/classify"; // Your Flask API endpoint
  
      fetch(flaskAPI, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: changeInfo.url })
      })
        .then((response) => response.json())
        .then((data) => {
          if (data.prediction === "Trojan") {
            chrome.action.setPopup({ tabId: tabId, popup: "popup.html" });
          }
        })
        .catch((err) => console.error("Error contacting Flask API:", err));
    }
  });
  