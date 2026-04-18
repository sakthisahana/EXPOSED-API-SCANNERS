const express = require('express');
const app = express();

// HARDCODED SECRET - VIOLATION
const STRIPE_SECRET_KEY = "sk_live_51N9abcd123456789123456";

app.post('/pay', (req, res) => {
    // Payment logic here
    console.log("Processing payment with key: " + STRIPE_SECRET_KEY);
});

app.listen(3000, () => {
    console.log('Server running');
});