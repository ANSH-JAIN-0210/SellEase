const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const bodyparser = require('body-parser')
const userRoutes = require('./routes/UserRoutes')

const app = express()
app.use(express.json())
app.use(cors())
app.use(bodyparser.json())

mongoose.connect("mongodb://localhost:27017/SellEase", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error: "));
db.once('open', () => console.log('Connected to mongoDB'))

app.use('/api', userRoutes)

const port = process.env.PORT || 5000
app.listen(port, () => console.log(`App listening on port: ${port}`));