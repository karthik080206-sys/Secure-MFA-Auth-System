console.log("Secure Auth System Static JS Loaded");

// Add any client-side interactivity here
document.addEventListener('DOMContentLoaded', () => {
    const button = document.querySelector('button');
    if (button) {
        button.addEventListener('click', () => {
            console.log("Button clicked!");
        });
    }
});
