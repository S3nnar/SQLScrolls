const express = require("express");
const router = express.Router();
const db = require("../utils/db");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const {ObjectId} = require("mongodb");
const postmark = require("postmark");
const reqBodyValidator = require("../middlewares/reqBodyValidator");
const {
    registerPOST,
    authenticatePOST,
    authenticateSWITCHaaiPOST,
    answerSqlPATCH,
    recoverPOST,
    resetPOST
} = require("../schemas/users");
const {checkIfFinished, checkIfNew, generateCertificate} = require("../utils/certificate");

const cors = require("cors");

router.use(cors());


async function findAuthenticatedUser(req) {
    const users = db.get().collection("users");
    return users.findOne({_id: new ObjectId(req.auth.userId)});
}

async function requireAdmin(req, res, next) {
    try {
        const currentUser = await findAuthenticatedUser(req);
        if (!currentUser || currentUser.isAdmin !== true) {
            return res.status(403).json({error: "Admin access required."});
        }
        req.currentUser = currentUser;
        return next();
    } catch (err) {
        return next(err);
    }
}

function sanitizeAdminResult(collection, items) {
    if (collection !== "users" && collection !== "users_archive") return items;
    return items.map((item) => {
        if (!item || typeof item !== "object") return item;
        const {password, resetPasswordToken, resetPasswordExpires, ...rest} = item;
        return rest;
    });
}

// /users/register
router.post("/register", reqBodyValidator(registerPOST), async function ({body: user}, res, next) {

    // Get Users Collections
    const users = db.get().collection("users");

    // Check if user is form the FHNW
    if ((user.username.endsWith("@fhnw.ch") || (user.username.endsWith(".fhnw.ch")))) return next("FHNW users shoud use institutional login!");

    // Check if user already exists
    if (await users.findOne({username: user.username})) return next("User already exists!");

    // Hash password
    user.password = bcrypt.hashSync(user.password, 10);

    // Add registration date
    user.registrationDate = new Date()

    // Initialize stars field with 0
    user.stars = 0;

    // Initialize timeLastActive field
    user.timeLastActive = new Date();

    // Initialize timeStarsEarned field
    user.timeStarsEarned = null;

    // Insert into Database
    users
        .insertOne(user)
        .then(() => {
            let {password, ...u} = user;
            return res.json(u);
        })
        .catch((err) => next(err));
});

// /users/self/stars
router.patch("/self/stars", async function (req, res, next) {
    const users = db.get().collection("users");

    // Extract the stars value from the request body
    const {stars} = req.body;

    // Validate the stars value to ensure it's a number and non-negative
    if (typeof stars !== 'number' || stars < 0) {
        return res.status(400).json({error: "Invalid stars value. It must be a non-negative number."});
    }

    try {
        // Update the user's stars value without returning the updated document
        await users.findOneAndUpdate(
            {_id: new ObjectId(req.auth.userId)}, // Find the user by ID
            {$set: {stars: stars}}              // Update only the stars field
        );
        return res.json({message: "stars updated successfully."});
    } catch (err) {
        console.error("Error updating stars:", err);
        next(err);
    }
});

router.patch("/self/timeLastActive", async function (req, res, next) {
    const users = db.get().collection("users");
    const userId = new ObjectId(req.auth.userId);
    const result = await users.findOneAndUpdate(
        {_id: userId},
        {$set: {timeLastActive: new Date()}},
        {returnDocument: "after"}
    );
    return res.json({message: "timeLastActive updated successfully."});
});

// /users/self/timeStarsEarned
router.patch("/self/timeStarsEarned", async function (req, res, next) {
    const users = db.get().collection("users");

    // No request body required, since we call this endpoint without any parameters
    // Also, no checking of incoming parameters required here

    try {
        // Set the timestamp to the current time in the backend
        await users.findOneAndUpdate(
            {_id: new ObjectId(req.auth.userId)}, // Find the user by ID
            {$set: {timeStarsEarned: new Date()}} // Set current time for timeStarsEarned
        );
        // Return success message
        return res.json({message: "timeStarsEarned timestamp updated successfully."});
    } catch (err) {
        console.error("Error updating timeStarsEarned timestamp:", err);
        next(err);
    }
});

// /users/self/classKey
router.patch("/self/classKey", async function (req, res, next) {
    const users = db.get().collection("users");

    // Extract the classKey from the request body
    const {classKey} = req.body;

    // Validate that the classKey is not empty
    if (!classKey || typeof classKey !== 'string' || classKey.trim() === '') {
        return res.status(400).json({error: "Invalid classKey. It must be a non-empty string."});
    }

    try {
        // Update the user's classKey value without returning the updated document
        await users.findOneAndUpdate(
            {_id: new ObjectId(req.auth.userId)}, // Find the user by ID
            {$set: {classKey: classKey}} // Update only the classKey field
        );
        return res.json({message: "classKey inserted successfully."});
    } catch (err) {
        console.error("Error inserting classKey:", err);
        next(err);
    }
});

// /users/self/togglePrivacy
router.patch("/self/togglePrivacy", async function (req, res, next) {
    const {makePrivate, aliasName} = req.body;  // Expects `makePrivate: true` or `false`, and `aliasName`
    const users = db.get().collection("users");

    try {
        // Find the user in the database
        const user = await users.findOne({_id: new ObjectId(req.auth.userId)});

        if (!user) {
            return res.status(404).json({error: "User not found."});
        }

        if (makePrivate) {
            // User wants to anonymize; use the aliasName from the request if provided, or the already saved one
            const newAliasName = user.aliasName || aliasName;

            await users.updateOne(
                {_id: user._id},
                {
                    $set: {
                        isPublic: false,
                        aliasName: newAliasName,
                    },
                }
            );
        } else {
            // User wants to be public again; set `isPublic` to true and leave `aliasName` unchanged
            await users.updateOne(
                {_id: user._id},
                {
                    $set: {isPublic: true},
                }
            );
        }

        // Return a success message
        return res.json({message: "Privacy setting updated successfully."});
    } catch (err) {
        console.error("Error toggling privacy:", err);
        next(err);
    }
});

// /users/authenticate
router.post("/authenticate", reqBodyValidator(authenticatePOST), async function ({body: value}, res, next) {

    // Get Users Collections
    const users = db.get().collection("users");
    const user = await users.findOne({username: value.username});

    // Login failed
    if (!user || !user.password || !bcrypt.compareSync(value.password, user.password)) return next("Username or password is incorrect");

    // Sign Token
    const token = jwt.sign({userId: user._id.toString()}, process.env.JWT_SECRET, {expiresIn: "365d"});
    const retVal = {token};
    return res.json(retVal);
});

// /users/authenticateSWITCHaai
router.post("/authenticateSWITCHaai", reqBodyValidator(authenticateSWITCHaaiPOST),
    async function ({headers: headers, body: value}, res, next) {
        // Parse the backend cookie
        let authCookie = null
        let parsedCookie = {}
        try {
            headers.cookie.split(';').map(item => item.split("=")).forEach(pair => {
                if (pair[0].trim() === 'sqlscrolls-auth') authCookie = pair.slice(1).join('=')
            })
            authCookie.split("|").map(pair => pair.split(":")).forEach(item => {
                parsedCookie[item[0]] = item[1]
            })
        } catch {
            console.log("auth COOKIES", headers.cookie)
            console.log("auth parsed: ", parsedCookie)
            console.error("No valid authentication cookie found for the API");
            return next("No valid authentication cookie found for the API");
        }

        // Compare cookie from frontend (value) with the one from backend
        for (const field of ["username", "uid", "pid", "org"]) {
            if ((!parsedCookie[field]) || (parsedCookie[field] !== value[field])) {
                console.log("auth COOKIES", headers.cookie)
                console.log("auth parsed: ", parsedCookie)
                console.error("User auth cookie incorrect (different from frontend) cookie = ", parsedCookie[field], " fontend = ", value[field]);
                return next("User auth cookie incorrect (different from frontend)");
            }
        }

        // Get Users Collections
        const users = db.get().collection("users");
        let user = await users.findOne({username: value.username});

        if (user) {
            let needUpdate = false

            // if switch data stored, compare it otherwise store it
            for (const field of ["uid", "pid", "org"]) {
                if (!user[field]) {
                    user[field] = value[field]
                    needUpdate = true
                } else {
                    if (user[field] !== value[field]) {
                        console.log("auth COOKIES", headers.cookie)
                        console.log("auth fontend: ", value)
                        console.error("User data icorrect (different from registration) user = ", user[field], " value = ", value[field])
                        return next("User data icorrect (different from registration)");
                    }
                }
            }
            // check display name changes
            for (const field of ["givenname", "surname"]) {
                if ((!user[field]) || (user[field] !== value[field])) {
                    user[field] = value[field]
                    needUpdate = true
                }
            }

            // add data if necessary
            if (needUpdate) {
                await users
                    .findOneAndUpdate(
                        {_id: user._id},
                        {$set: value},
                        {returnDocument: "after"}
                    )
                    .catch((err) => {
                        console.error("update error ", err);
                        next(err)
                    });
            }
        } else {
            value.password = null
            // Add registration date
            value.registrationDate = new Date()
            // register user
            await users
                .insertOne(value)
                .catch((err) => {
                    console.error("insert error ", err);
                    next(err)
                });
            user = value;
        }

        // Sign Token
        const switchaai = true
        const token = jwt.sign({userId: user._id}, process.env.JWT_SECRET, {expiresIn: "365d"});
        const retVal = {token, switchaai};
        return res.json(retVal);
    });

// /users/self
router.get("/self", async function (req, res, next) {
    // Get Users Collections
    const users = db.get().collection("users");
    const user = await users.findOne({_id: new ObjectId(req.auth.userId)});
    const {password, ...retVal} = user;
    return res.json(retVal);
});

// /users/all
router.get("/all", async function (req, res, next) {
    try {
        // Get Users Collection
        const users = db.get().collection("users");

        // Calculate the date of one year prior
        const oneYearAgo = new Date();
        oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);

        // Find all users
        const allUsers = await users.find(
            {timeLastActive: {$gte: oneYearAgo}}, // Include only users active in the last year
            {projection: {password: 0}})  // Exclude password field
            .sort({stars: -1, timeStarsEarned: 1}) // Sort by stars (decending) and timeStarsEarned (ascending)
            .toArray();

        // Return users
        return res.json(allUsers);
    } catch (err) {
        next(err);
    }
});

// /users/classFiltered
router.get("/classFiltered", async function (req, res, next) {
    try {
        // Get Users Collection
        const users = db.get().collection("users");

        // Retrieve the requesting user's data
        const currentUser = await users.findOne({_id: new ObjectId(req.auth.userId)});

        // Check if the user exists
        if (!currentUser) {
            return res.status(404).send("User not found");
        }

        // If user exists but does not have a classKey, return only their data as an array
        if (!currentUser.classKey) {
            const {password, ...userData} = currentUser;  // Exclude the password
            return res.json([userData]);  // Return the user data as an array
        }

        // Proceed to retrieve users with the same classKey if classKey exists
        const filteredUsers = await users
            .find({classKey: currentUser.classKey}, {projection: {password: 0}})
            .sort({stars: -1, timeStarsEarned: 1})  // Sort by stars in descending order and timeStarsEarned (ascending)
            .toArray();

        // Return the filtered list of users
        return res.json(filteredUsers);
    } catch (err) {
        next(err);
    }
});

// /users/certificate
router.patch("/self/certificate", async function (req, res, next) {
    // Get Users Certificate if finished Game
    const users = db.get().collection("users");
    const user = await users.findOne({_id: new ObjectId(req.auth.userId)});

    try {

        let progression = req.body.progression
        if (!checkIfFinished(user, progression)) {
            return res.json({'success': false, 'reason': "GAME_NOT_FINISHED"})
        }
        if (!checkIfNew(user, progression)) {
            return res.json({'success': false, 'reason': "CERTIFICATE_ALREADY_GENERATED"})
        }
        let newCertificate = generateCertificate(user, progression)
        console.log(newCertificate)

        // Add certificate to user
        users
            .findOneAndUpdate(
                {_id: user._id},
                {$addToSet: {[`certificates`]: newCertificate}},
                {returnDocument: "after"}
            )
            .then(v => {
                return res.json(newCertificate);
            })
            .catch((err) => next(err));

    } catch (err) {
        console.error("Error parsing progression:", err);
        next(err)
    }

});

// /users/self/answer_sql
router.patch("/self/answer_sql", reqBodyValidator(answerSqlPATCH), async function (req, res, next) {
    try {
        const body = req.body;
        const users = db.get().collection("users");
        const user = await users.findOne({_id: new ObjectId(req.auth.userId)});

        if (!user) {
            return res.status(404).json({error: "User not found"});
        }

        const payload = {
            correct: JSON.parse(body.correct),
            date: Date.now(),
            query: body.query,
            startTime: body.startTime,
            endTime: body.endTime,
        };

        const result = await users.findOneAndUpdate(
            {_id: user._id},
            {$addToSet: {[`history.${body.task}`]: payload}},
            {returnDocument: "after"}
        );

        const {password, ...userData} = result.value || {};
        return res.json(userData);
    } catch (err) {
        console.error("🔥 Error in PATCH /self/answer_sql:", err);
        return res.status(500).json({error: "Internal server error"});
    }
});

// Delete history
router.patch("/self/restart", async function (req, res, next) {
    const users = db.get().collection("users");
    const archives = db.get().collection("users_archive");

    const user = await users.findOne({_id: new ObjectId(req.auth.userId)});

    if (!user) {
        return res.status(404).json({error: "User not found."});
    }

    // Archive current user
    const clone = {...user, _id: {_id: user._id, date: Date.now()}};

    await archives.insertOne(clone).catch((err) => {
        console.error("insert error ", err);
        return next(err);
    });

    // Empty history
    users
        .findOneAndUpdate(
            {_id: user._id},
            {$unset: {history: 1}},
            {returnDocument: "after"}
        )
        .then(({value}) => {
            const {password, ...sanitizedUser} = value;
            console.log("Deleted history for user", sanitizedUser.username);
            return res.json(sanitizedUser);
        })
        .catch((err) => next(err));
});

// /users/recover
// A reset link is created and an options object is created defining the from, to, subject and text and an email is sent to the user using the sendgrid package.
router.post("/recover", reqBodyValidator(recoverPOST), async function (req, res, next) {
    // Get Users Collections
    const users = db.get().collection("users");
    users
        .findOneAndUpdate(
            {username: req.body.username},
            {
                $set: {
                    resetPasswordToken: crypto.randomBytes(20).toString("hex"),
                    resetPasswordExpires: Date.now() + 3600000,
                },
            },
            {returnDocument: "after"}
        )
        .then(async ({value: user}) => {
            if (!user) return next("User not found");
            // Send Mail if its not invoked by JEST
            if (!process.env.JEST_WORKER_ID) {
                const client = new postmark.ServerClient(process.env.POSTMARK_API_KEY);
                const link = (process.env.IO_URL) + "/?action=resetPassword&token=" + user.resetPasswordToken;
                await client.sendEmail({
                    From: process.env.FROM_SENDER,
                    To: user.username,
                    Subject: "Password change request",
                    HtmlBody: `Hi ${user.username} \n 
    Please click on the following link <a href="${link}">${link}</a> to reset your password. \n\n 
    If you did not request this, please ignore this email and your password will remain unchanged.\n`,
                    MessageStream: "outbound",
                });
            }
            return res.json({message: "Password reset link sent!"});
        })
        .catch((err) => next(err));
});

// /users/reset
// Reset the password
router.post("/reset", reqBodyValidator(resetPOST), async function ({body: value}, res, next) {
    // Get Users Collections
    const users = db.get().collection("users");
    const password = bcrypt.hashSync(value.password, 10);
    users
        .findOneAndUpdate(
            {resetPasswordToken: value.token, resetPasswordExpires: {$gt: Date.now()}},
            {
                $set: {
                    password: password,
                    resetPasswordToken: undefined,
                    resetPasswordExpires: undefined,
                },
            },
            {returnDocument: "after"}
        )
        .then(async ({value: user}) => {
            if (!user) return next("Token invalid or expired! Request a new one!");
            // Send Mail if its not invoked by JEST
            if (!process.env.JEST_WORKER_ID) {
                const client = new postmark.ServerClient(process.env.POSTMARK_API_KEY);
                await client.sendEmail({
                    From: process.env.FROM_SENDER,
                    To: user.username,
                    subject: "Your password has been changed",
                    HtmlBody: `Hi ${user.username} \n 
          This is a confirmation that the password for your account ${user.username} has just been changed.\n`,
                    MessageStream: "outbound",
                });
            }

            return res.json({message: "Password reset was successfully!"});
        })
        .catch((err) => next(err));
});

router.get("/recommend-task", async function (req, res) {
    console.log("Initializing routing");
    const username = req.query.username;
    console.log("Received request to recommend task for username:", username);

    if (!username) {
        console.log("Username is required but not provided.");
        return res.status(400).json({error: "Username is required"});
    }

    try {
        const response = await fetch(`http://stg-model:5001/recommend-task?userID=${username}`);
        const data = await response.text();
        console.log("Response from recommendation API:", data);

        // If the response status is not OK, return the status and data as error
        if (!response.ok) {
            console.error("Error response from recommendation API:", response.status, data);
            return res.status(response.status).send(data);
        }

        res.status(response.status).send(data); // Send back the same status and data received from stg-model API
    } catch (error) {
        console.error("Error occurred while recommending task:", error);
        res.status(500).json({error: "Internal server error while recommending task", details: error.message});
    }
});

// export

router.get("/admin/operations/summary", requireAdmin, async function (req, res, next) {
    try {
        const users = db.get().collection("users");
        const oneWeekAgo = new Date();
        oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

        const [totalUsers, activeUsersLast7Days, admins] = await Promise.all([
            users.countDocuments({}),
            users.countDocuments({timeLastActive: {$gte: oneWeekAgo}}),
            users.countDocuments({isAdmin: true}),
        ]);

        return res.json({
            totalUsers,
            activeUsersLast7Days,
            admins,
            generatedAt: new Date(),
        });
    } catch (err) {
        return next(err);
    }
});

router.get("/admin/operations/recent-users", requireAdmin, async function (req, res, next) {
    try {
        const users = db.get().collection("users");
        const limit = Math.min(Number(req.query.limit) || 25, 100);
        const recentUsers = await users
            .find({}, {projection: {password: 0, resetPasswordToken: 0, resetPasswordExpires: 0}})
            .sort({registrationDate: -1})
            .limit(limit)
            .toArray();

        return res.json(recentUsers);
    } catch (err) {
        return next(err);
    }
});

router.patch("/admin/operations/users/:userId/stars", requireAdmin, async function (req, res, next) {
    try {
        const users = db.get().collection("users");
        const userId = req.params.userId;
        const stars = Number(req.body.stars);

        if (!ObjectId.isValid(userId)) return res.status(400).json({error: "Invalid user id."});
        if (!Number.isFinite(stars) || stars < 0) {
            return res.status(400).json({error: "Stars must be a non-negative number."});
        }

        const result = await users.findOneAndUpdate(
            {_id: new ObjectId(userId)},
            {$set: {stars}},
            {returnDocument: "after", projection: {password: 0, resetPasswordToken: 0, resetPasswordExpires: 0}}
        );

        if (!result.value) return res.status(404).json({error: "User not found."});
        return res.json(result.value);
    } catch (err) {
        return next(err);
    }
});

router.post("/admin/query", requireAdmin, async function (req, res, next) {
    try {
        const {collection, action = "find", filter, projection, sort, limit, pipeline, update, replacement, document, documents, options, command} = req.body;
        const allowedCollections = ["users", "users_archive"];
        const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 1000);

        if (action === "runCommand") {
            if (!command || typeof command !== "object") {
                return res.status(400).json({error: "Command must be a JSON object."});
            }
            const result = await db.get().command(command);
            return res.json({action, result});
        }

        if (!allowedCollections.includes(collection)) {
            return res.status(400).json({error: "Collection is not allowed."});
        }

        const coll = db.get().collection(collection);
        const safeFilter = filter && typeof filter === "object" ? filter : {};
        const safeProjection = projection && typeof projection === "object" ? projection : {};
        const safeSort = sort && typeof sort === "object" ? sort : {_id: -1};
        const safeOptions = options && typeof options === "object" ? options : {};

        let result;
        switch (action) {
            case "aggregate":
                if (!Array.isArray(pipeline)) return res.status(400).json({error: "Pipeline must be an array."});
                result = await coll.aggregate(pipeline, safeOptions).limit(safeLimit).toArray();
                return res.json({action, collection, count: result.length, result: sanitizeAdminResult(collection, result)});
            case "find":
                result = await coll.find(safeFilter, {projection: safeProjection, ...safeOptions}).sort(safeSort).limit(safeLimit).toArray();
                return res.json({action, collection, count: result.length, result: sanitizeAdminResult(collection, result)});
            case "updateOne":
                if (!update || typeof update !== "object") return res.status(400).json({error: "Update must be a JSON object."});
                result = await coll.updateOne(safeFilter, update, safeOptions);
                return res.json({action, collection, matchedCount: result.matchedCount, modifiedCount: result.modifiedCount, upsertedId: result.upsertedId});
            case "updateMany":
                if (!update || typeof update !== "object") return res.status(400).json({error: "Update must be a JSON object."});
                result = await coll.updateMany(safeFilter, update, safeOptions);
                return res.json({action, collection, matchedCount: result.matchedCount, modifiedCount: result.modifiedCount, upsertedId: result.upsertedId});
            case "replaceOne":
                if (!replacement || typeof replacement !== "object") return res.status(400).json({error: "Replacement must be a JSON object."});
                result = await coll.replaceOne(safeFilter, replacement, safeOptions);
                return res.json({action, collection, matchedCount: result.matchedCount, modifiedCount: result.modifiedCount, upsertedId: result.upsertedId});
            case "insertOne":
                if (!document || typeof document !== "object") return res.status(400).json({error: "Document must be a JSON object."});
                result = await coll.insertOne(document, safeOptions);
                return res.json({action, collection, insertedId: result.insertedId});
            case "insertMany":
                if (!Array.isArray(documents)) return res.status(400).json({error: "Documents must be an array."});
                result = await coll.insertMany(documents, safeOptions);
                return res.json({action, collection, insertedCount: result.insertedCount, insertedIds: result.insertedIds});
            case "deleteOne":
                result = await coll.deleteOne(safeFilter, safeOptions);
                return res.json({action, collection, deletedCount: result.deletedCount});
            case "deleteMany":
                result = await coll.deleteMany(safeFilter, safeOptions);
                return res.json({action, collection, deletedCount: result.deletedCount});
            default:
                return res.status(400).json({error: "Unsupported action."});
        }
    } catch (err) {
        return next(err);
    }
});

router.patch("/admin/operations/users/bulk-update", requireAdmin, async function (req, res, next) {
    try {
        const users = db.get().collection("users");
        const {
            userIds = [],
            usernames = [],
            update = {},
            applyToRelatedCollections = true,
            relatedCollections = ["users_archive"],
        } = req.body;

        const validUserIds = userIds.filter((id) => ObjectId.isValid(id)).map((id) => new ObjectId(id));
        const validUsernames = usernames.filter((name) => typeof name === "string" && name.trim().length > 0);

        if (!validUserIds.length && !validUsernames.length) {
            return res.status(400).json({error: "Provide at least one userId or username."});
        }
        if (!update || typeof update !== "object" || Object.keys(update).length === 0) {
            return res.status(400).json({error: "Update operators are required."});
        }

        const userFilter = {$or: []};
        if (validUserIds.length) userFilter.$or.push({_id: {$in: validUserIds}});
        if (validUsernames.length) userFilter.$or.push({username: {$in: validUsernames}});

        const userUpdateResult = await users.updateMany(userFilter, update);

        const relatedResults = [];
        if (applyToRelatedCollections && Array.isArray(relatedCollections)) {
            for (const collectionName of relatedCollections) {
                if (collectionName !== "users_archive") continue;
                const collection = db.get().collection(collectionName);
                const relatedFilter = {
                    $or: [
                        {username: {$in: validUsernames}},
                        {"_id._id": {$in: validUserIds}},
                    ],
                };
                const relatedUpdateResult = await collection.updateMany(relatedFilter, update);
                relatedResults.push({
                    collection: collectionName,
                    matchedCount: relatedUpdateResult.matchedCount,
                    modifiedCount: relatedUpdateResult.modifiedCount,
                });
            }
        }

        return res.json({
            users: {
                matchedCount: userUpdateResult.matchedCount,
                modifiedCount: userUpdateResult.modifiedCount,
            },
            relatedCollections: relatedResults,
        });
    } catch (err) {
        return next(err);
    }
});

module.exports = router;
