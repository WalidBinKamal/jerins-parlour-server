require('dotenv').config()
const express = require('express')
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const cors = require('cors')

//Configuration
const app = express()
const port = process.env.PORT || 5000
const jwtSecret = process.env.JWT_SECRET


// middleware
app.use(cors({
    origin: ["http://localhost:5173"],
    credentials: true,
}))
app.use(express.json())
app.use(cookieParser())

app.get('/', (req, res) => {
    res.send('Beauty is a inner thing.')
})

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.7rlpdj6.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// function to create token
const createToken = (email) => {
    return jwt.sign({ email }, jwtSecret, { expiresIn: "7d" })
}

// middleware to verify token
const verifyToken = (req, res, next) => {
    const token = req.cookies.token
    if (!token) {
        return res.status(401).send({ message: "Unauthorized" })
    }
    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: "Unauthorized" })
        }
        req.user = decoded
        next()
    })
}

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();
        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");

        const serviceCollection = client.db("parlourDB").collection("services")
        const reviewCollection = client.db("parlourDB").collection("reviews")
        const userCollection = client.db("parlourDB").collection("users")
        const bookingCollection = client.db("parlourDB").collection("bookings")

        // Services related apis
        app.get('/services', async (req, res) => {
            const result = await serviceCollection.find().toArray()
            res.send(result)
        })
        app.get('/service/:id', verifyToken, async (req, res) => {
            const id = req.params.id
            const query = { _id: new ObjectId(id) }
            const result = await serviceCollection.findOne(query)
            res.send(result)
        })

        // booking realted apis
        app.post('/booking', verifyToken, async (req, res) => {
            const data = req.body
            const result = await bookingCollection.insertOne(data)
            res.send(result)
        })
        app.get('/booking/:email', verifyToken, async (req, res) => {
            const email = req.params.email
            const query = { email: email }
            const result = await bookingCollection.find(query).toArray()
            res.send(result)
        })

        // Review related apis
        app.get('/reviews', async (req, res) => {
            const result = await reviewCollection.find().toArray()
            res.send(result)
        })
        app.post('/reviews', verifyToken, async (req, res) => {
            const data = req.body
            const result = await reviewCollection.insertOne(data)
            res.send(result)
        })

        // user related apis
        app.get('/users/:email', verifyToken, async (req, res) => {
            const email = req.params.email
            const query = { email: email }
            const result = await userCollection.findOne(query)
            if (!result) {
                return res.status(404).json({ error: "User not found" });
            }
            if (email !== req.user.email) {
                return res.status(403).json({ error: "Forbidden Access" });
            }
            const { hashedPassword, ...user } = result
            res.send(user)
        })

        app.put('/users/:email', async (req, res) => {
            const email = req.params.email;
            const updateData = req.body;

            const user = await userCollection.findOne({ email: email });

            let body = {};

            ['firstName', 'lastName', 'image'].forEach(field => {
                if (
                    updateData[field] !== undefined &&
                    (!user || updateData[field] !== user[field])
                ) {
                    body[field] = updateData[field];
                }
            });

            if (updateData.password && updateData.password.trim() !== '') {
                const salt = await bcrypt.genSalt(10);
                body.password = await bcrypt.hash(updateData.password, salt);
            }

            if (Object.keys(body).length === 0) {
                return res.send({ message: 'No changes detected' });
            }

            const result = await userCollection.updateOne(
                { email: email },
                { $set: body },
                { upsert: true }
            );

            // Add message property to result for client readability
            if (result.upsertedCount > 0) {
                result.message = 'User created successfully';
            } else {
                result.message = 'User updated successfully';
            }

            res.send(result);
        });

        // Auth related apis
        // registration
        app.post('/api/auth/register', async (req, res) => {
            const { firstName, lastName, email, password } = req.body

            const existingUser = await userCollection.findOne({ email: email })
            if (existingUser) {
                return res.status(400).send({ message: "Email already exists" })
            }

            const hashedPassword = await bcrypt.hash(password, 10)
            const result = await userCollection.insertOne({ firstName, lastName, email, hashedPassword })

            const token = createToken(email)
            res.cookie("token", token, {
                httpOnly: true,
                sameSite: "strict",
                secure: false,
            })
            res.send(result)
        })
        // Login
        app.post('/api/auth/login', async (req, res) => {
            const { email, password } = req.body
            const query = { email: email }

            const user = await userCollection.findOne(query)
            if (!user) {
                return res.status(400).send({ message: "Invalid email or password" })
            }

            const isMatch = await bcrypt.compare(password, user.hashedPassword)
            if (!isMatch) {
                return res.status(400).send({ message: "Invalid email or password" })
            }

            const token = createToken(email)
            res.cookie("token", token, {
                httpOnly: true,
                sameSite: "strict",
                secure: false,
            })
            res.send({ message: "Logged in" })
        })
        // check user
        app.get("/api/auth/checkUser", verifyToken, (req, res) => {
            res.send({ loggedIn: true, email: req.user.email })
        })
        // logout
        app.post('/api/auth/logout', (req, res) => {
            res.clearCookie("token")
            res.send({ message: "Logged Out" })
        })


    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.listen(port, () => {
    console.log(`Defination of beauty is on port: ${port}`)
})
