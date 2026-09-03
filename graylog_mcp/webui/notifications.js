let region;

function notificationRegion() {
  if (!region) {
    region = document.createElement("div");
    region.className = "notification-region";
    region.setAttribute("aria-live", "polite");
    document.body.append(region);
  }
  return region;
}

export function notify(message, kind = "info") {
  const item = document.createElement("div");
  item.className = `notification ${kind}`;
  item.textContent = message;
  notificationRegion().append(item);
  setTimeout(() => item.remove(), 5000);
}
