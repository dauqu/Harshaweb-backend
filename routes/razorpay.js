const express = require('express');
const app = express();

//Create Razorpay instance
const Razorpay = require('razorpay');
const { router } = require('websocket');


//Create express js server http
app.use(express.json());

//Create express js server http
app.use(express.urlencoded({ extended: true }));

app.get('/', async (req, res) => {
    try {
        const instance = new Razorpay({
            key_id: "rzp_test_fYtFrx227DT8xU",
            key_secret: "731uLiOTTEWp1GpSrVHfTfKS",
        });

        const options = {
            amount: 50000, // amount in smallest currency unit
            currency: "INR",
            receipt: "receipt_order_74394",
        };

        const order = await instance.orders.create(options);

        if (!order) return res.status(500).send("Some error occured");

        res.json(order);
    } catch (error) {
        res.status(500).send(error);
    }
})

module.exports = router;