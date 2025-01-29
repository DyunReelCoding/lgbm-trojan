document.querySelector(".back").addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      chrome.tabs.update(tabs[0].id, { url: "chrome://newtab" });
    });
  });
  
  document.querySelector(".continue").addEventListener("click", () => {
    window.close(); // Closes the popup
  });
  