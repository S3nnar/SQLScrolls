require("dotenv").config();
const bcrypt = require("bcryptjs");
const db = require("../utils/db");

async function createOrPromoteAdmin() {
    const username = process.env.ADMIN_BOOTSTRAP_USERNAME;
    const password = process.env.ADMIN_BOOTSTRAP_PASSWORD;

    if (!username || !password) {
        throw new Error("ADMIN_BOOTSTRAP_USERNAME und ADMIN_BOOTSTRAP_PASSWORD müssen gesetzt sein.");
    }

    if (password.length < 16) {
        throw new Error("ADMIN_BOOTSTRAP_PASSWORD muss mindestens 16 Zeichen haben.");
    }

    await db.connect();
    const users = db.get().collection("users");
    const existing = await users.findOne({username});

    if (existing) {
        await users.updateOne(
            {_id: existing._id},
            {$set: {isAdmin: true, timeLastActive: existing.timeLastActive || new Date()}}
        );
        console.log(`Admin-Rechte für bestehenden User gesetzt: ${username}`);
    } else {
        const hashedPassword = bcrypt.hashSync(password, 12);
        await users.insertOne({
            username,
            password: hashedPassword,
            isAdmin: true,
            stars: 0,
            registrationDate: new Date(),
            timeLastActive: new Date(),
            timeStarsEarned: null,
        });
        console.log(`Admin-User angelegt: ${username}`);
    }

    await db.close();
}

createOrPromoteAdmin()
    .then(() => process.exit(0))
    .catch(async (error) => {
        console.error(error.message);
        try {
            await db.close();
        } catch {}
        process.exit(1);
    });
