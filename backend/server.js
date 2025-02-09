const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
require('dotenv').config();

// Create Express app
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Serve static files from the parent directory
app.use(express.static(path.join(__dirname, '..')));

// MongoDB Atlas Connection
const connectToMongoDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000
        });
        console.log('🌍 Connected to MongoDB Atlas successfully');
    } catch (error) {
        console.error('❌ MongoDB Atlas connection error:', error.message);
        // If connection fails, retry after 5 seconds
        console.log('⏳ Retrying connection in 5 seconds...');
        setTimeout(connectToMongoDB, 5000);
    }
};

// Initial connection
connectToMongoDB();

// Handle connection events
mongoose.connection.on('connected', () => {
    console.log('🔄 MongoDB Atlas connection established');
});

mongoose.connection.on('error', (err) => {
    console.error('❌ MongoDB Atlas connection error:', err.message);
});

mongoose.connection.on('disconnected', () => {
    console.log('❌ MongoDB Atlas disconnected. Attempting to reconnect...');
    setTimeout(connectToMongoDB, 5000);
});

// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    fullName: { type: String, required: true },
    bio: { type: String, default: '' },
    location: { type: String, default: '' },
    joinedDate: { type: Date, default: Date.now },
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    tweetsCount: { type: Number, default: 0 }
});

// Tweet Schema (renamed from Post)
const tweetSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true, maxLength: 280 },
    category: { type: String, required: true, enum: ['Health', 'Career', 'Relationships', 'Mental Health', 'General'] },
    isAnonymous: { type: Boolean, default: false },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    retweets: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    replies: [{
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        content: { type: String, required: true, maxLength: 280 },
        createdAt: { type: Date, default: Date.now }
    }],
    hashtags: [{ type: String }],
    createdAt: { type: Date, default: Date.now }
});

// Health Problem Schema
const healthProblemSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    problem: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

// Notification Schema
const notificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, required: true, enum: ['like', 'retweet', 'reply', 'follow'] },
    fromUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    tweetId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tweet' },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

// Create models
const User = mongoose.model('User', userSchema);
const HealthProblem = mongoose.model('HealthProblem', healthProblemSchema);
const Tweet = mongoose.model('Tweet', tweetSchema);
const Notification = mongoose.model('Notification', notificationSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Access denied' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Auth Routes
app.post('/api/signup', async (req, res) => {
    try {
        const { email, password, username, fullName } = req.body;

        // Validate all required fields
        if (!email || !password || !username || !fullName) {
            return res.status(400).json({ 
                message: 'All fields are required',
                missing: {
                    email: !email,
                    password: !password,
                    username: !username,
                    fullName: !fullName
                }
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        // Validate password length
        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters long' });
        }

        // Validate username format (alphanumeric and underscore only)
        const usernameRegex = /^[a-zA-Z0-9_]+$/;
        if (!usernameRegex.test(username)) {
            return res.status(400).json({ message: 'Username can only contain letters, numbers, and underscores' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            if (existingUser.email === email) {
                return res.status(400).json({ message: 'Email already exists' });
            }
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const user = new User({
            email,
            password: hashedPassword,
            username,
            fullName
        });

        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            token,
            userId: user._id,
            username: user.username,
            fullName: user.fullName
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Error creating user', error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ token, userId: user._id });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
});

// Protected Routes
app.post('/api/health-problem', authenticateToken, async (req, res) => {
    try {
        const { problem } = req.body;
        
        if (!problem) {
            return res.status(400).json({ message: 'Problem description is required' });
        }

        const healthProblem = new HealthProblem({
            userId: req.user.userId,
            problem
        });
        
        await healthProblem.save();
        res.status(201).json({ message: 'Health problem saved successfully' });
    } catch (error) {
        console.error('Health problem error:', error);
        res.status(500).json({ message: 'Error saving health problem', error: error.message });
    }
});

// Tweet Routes
app.post('/api/tweets', authenticateToken, async (req, res) => {
    try {
        const { content, isAnonymous, category } = req.body;

        if (!content) {
            return res.status(400).json({ message: 'Tweet content is required' });
        }

        if (!category) {
            return res.status(400).json({ message: 'Tweet category is required' });
        }

        if (content.length > 280) {
            return res.status(400).json({ message: 'Tweet cannot exceed 280 characters' });
        }

        // Extract hashtags from content
        const hashtags = content.match(/#[a-zA-Z0-9_]+/g) || [];

        const tweet = new Tweet({
            userId: req.user.userId,
            content,
            category,
            isAnonymous,
            hashtags: hashtags.map(tag => tag.slice(1))
        });

        await tweet.save();

        // Increment user's tweet count
        await User.findByIdAndUpdate(req.user.userId, { $inc: { tweetsCount: 1 } });

        // Populate user information before sending response
        await tweet.populate('userId', 'username fullName');

        res.status(201).json({ message: 'Tweet posted successfully', tweet });
    } catch (error) {
        console.error('Tweet creation error:', error);
        res.status(500).json({ message: 'Error posting tweet', error: error.message });
    }
});

// Get Timeline Tweets with category filter
app.get('/api/timeline', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20, category, filter = 'all' } = req.query;
        const user = await User.findById(req.user.userId);
        
        let query = {};

        // Apply filters based on the filter parameter
        if (filter === 'following') {
            query = {
                userId: { $in: [...user.following, user._id] }
            };
        } else if (filter === 'hashtags' && req.query.hashtags) {
            query = {
                hashtags: { $in: req.query.hashtags.split(',') }
            };
        }
        // If filter is 'all' or not specified, no additional query conditions needed

        // Add category filter if provided
        if (category && category !== 'all') {
            query.category = category;
        }

        // Use lean() for better performance when we don't need Mongoose documents
        const tweets = await Tweet.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .populate('userId', 'username fullName')
            .populate('replies.userId', 'username fullName')
            .lean()
            .exec();

        // Get total count for pagination
        const total = await Tweet.countDocuments(query);

        // Add additional user-specific data
        const tweetsWithUserData = tweets.map(tweet => ({
            ...tweet,
            isLiked: tweet.likes.some(id => id.toString() === req.user.userId),
            isRetweeted: tweet.retweets.some(id => id.toString() === req.user.userId),
            isOwner: tweet.userId._id.toString() === req.user.userId
        }));

        res.json({
            tweets: tweetsWithUserData,
            totalPages: Math.ceil(total / limit),
            currentPage: parseInt(page),
            hasMore: page * limit < total
        });
    } catch (error) {
        console.error('Error fetching timeline:', error);
        res.status(500).json({ 
            message: 'Error fetching timeline', 
            error: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// Like/Unlike Tweet
app.post('/api/tweets/:tweetId/like', authenticateToken, async (req, res) => {
    try {
        const tweet = await Tweet.findById(req.params.tweetId);
        if (!tweet) {
            return res.status(404).json({ message: 'Tweet not found' });
        }

        const likeIndex = tweet.likes.indexOf(req.user.userId);
        if (likeIndex > -1) {
            tweet.likes.splice(likeIndex, 1);
        } else {
            tweet.likes.push(req.user.userId);
            // Create notification for the tweet owner if it's not the same user
            if (tweet.userId.toString() !== req.user.userId) {
                const notification = new Notification({
                    userId: tweet.userId,
                    type: 'like',
                    fromUser: req.user.userId,
                    tweetId: tweet._id
                });
                await notification.save();
            }
        }

        // Save without validation since we're not modifying required fields
        await tweet.save({ validateBeforeSave: false });
        res.json({ message: 'Tweet like updated', liked: likeIndex === -1 });
    } catch (error) {
        console.error('Like error:', error);
        res.status(500).json({ message: 'Error updating like', error: error.message });
    }
});

// Retweet
app.post('/api/tweets/:tweetId/retweet', authenticateToken, async (req, res) => {
    try {
        const tweet = await Tweet.findById(req.params.tweetId);
        if (!tweet) {
            return res.status(404).json({ message: 'Tweet not found' });
        }

        const retweetIndex = tweet.retweets.indexOf(req.user.userId);
        if (retweetIndex > -1) {
            tweet.retweets.splice(retweetIndex, 1);
        } else {
            tweet.retweets.push(req.user.userId);
            // Create notification for the tweet owner if it's not the same user
            if (tweet.userId.toString() !== req.user.userId) {
                const notification = new Notification({
                    userId: tweet.userId,
                    type: 'retweet',
                    fromUser: req.user.userId,
                    tweetId: tweet._id
                });
                await notification.save();
            }
        }

        // Save without validation since we're not modifying required fields
        await tweet.save({ validateBeforeSave: false });
        res.json({ message: 'Retweet updated', retweeted: retweetIndex === -1 });
    } catch (error) {
        console.error('Retweet error:', error);
        res.status(500).json({ message: 'Error updating retweet', error: error.message });
    }
});

// Reply to Tweet
app.post('/api/tweets/:tweetId/reply', authenticateToken, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content) {
            return res.status(400).json({ message: 'Reply content is required' });
        }

        if (content.length > 280) {
            return res.status(400).json({ message: 'Reply cannot exceed 280 characters' });
        }

        const tweet = await Tweet.findById(req.params.tweetId);
        if (!tweet) {
            return res.status(404).json({ message: 'Tweet not found' });
        }

        tweet.replies.push({
            userId: req.user.userId,
            content
        });

        // Create notification for the tweet owner if it's not the same user
        if (tweet.userId.toString() !== req.user.userId) {
            const notification = new Notification({
                userId: tweet.userId,
                type: 'reply',
                fromUser: req.user.userId,
                tweetId: tweet._id
            });
            await notification.save();
        }

        await tweet.save();
        res.status(201).json({ message: 'Reply added successfully', tweet });
    } catch (error) {
        console.error('Reply error:', error);
        res.status(500).json({ message: 'Error adding reply', error: error.message });
    }
});

// Profile Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId)
            .select('-password')
            .populate('following', 'username fullName')
            .populate('followers', 'username fullName');

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ message: 'Error fetching profile', error: error.message });
    }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { fullName, bio, location } = req.body;
        
        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { fullName, bio, location },
            { new: true }
        ).select('-password');

        res.json(user);
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ message: 'Error updating profile', error: error.message });
    }
});

// Profile Tweets Routes
app.get('/api/profile/tweets', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        
        const tweets = await Tweet.find({ userId: req.user.userId })
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .populate('userId', 'username fullName');

        res.json({ tweets });
    } catch (error) {
        console.error('Error fetching profile tweets:', error);
        res.status(500).json({ message: 'Error fetching tweets', error: error.message });
    }
});

app.get('/api/profile/replies', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        
        const tweets = await Tweet.find({ 'replies.userId': req.user.userId })
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .populate('userId', 'username fullName')
            .populate('replies.userId', 'username fullName');

        res.json({ tweets });
    } catch (error) {
        console.error('Error fetching replies:', error);
        res.status(500).json({ message: 'Error fetching replies', error: error.message });
    }
});

app.get('/api/profile/likes', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        
        const tweets = await Tweet.find({ likes: req.user.userId })
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .populate('userId', 'username fullName');

        res.json({ tweets });
    } catch (error) {
        console.error('Error fetching liked tweets:', error);
        res.status(500).json({ message: 'Error fetching likes', error: error.message });
    }
});

// Explore Routes
app.get('/api/explore/:type', authenticateToken, async (req, res) => {
    try {
        const { type } = req.params;
        const { page = 1, limit = 20 } = req.query;
        let tweets;

        switch (type) {
            case 'top':
                tweets = await Tweet.aggregate([
                    {
                        $addFields: {
                            likesCount: { $size: "$likes" },
                            retweetsCount: { $size: "$retweets" }
                        }
                    },
                    {
                        $sort: {
                            likesCount: -1,
                            retweetsCount: -1,
                            createdAt: -1
                        }
                    },
                    { $skip: (page - 1) * limit },
                    { $limit: parseInt(limit) }
                ]).exec();

                // Populate user info after aggregation
                tweets = await Tweet.populate(tweets, { path: 'userId', select: 'username fullName' });
                break;
            
            case 'latest':
                tweets = await Tweet.find()
                    .sort({ createdAt: -1 })
                    .skip((page - 1) * limit)
                    .limit(limit)
                    .populate('userId', 'username fullName');
                break;
            
            case 'people':
                const users = await User.find()
                    .sort({ tweetsCount: -1 })
                    .skip((page - 1) * limit)
                    .limit(limit)
                    .select('-password');
                return res.json({ users });
            
            default:
                return res.status(400).json({ message: 'Invalid explore type' });
        }

        res.json({ tweets });
    } catch (error) {
        console.error('Error exploring tweets:', error);
        res.status(500).json({ message: 'Error exploring tweets', error: error.message });
    }
});

// Search Routes
app.get('/api/search', authenticateToken, async (req, res) => {
    try {
        const { q, type = 'top', page = 1, limit = 20 } = req.query;
        
        if (!q) {
            return res.status(400).json({ message: 'Search query is required' });
        }

        const query = {
            $or: [
                { content: { $regex: q, $options: 'i' } },
                { hashtags: { $regex: q.replace('#', ''), $options: 'i' } }
            ]
        };

        let tweets;
        switch (type) {
            case 'top':
                tweets = await Tweet.find(query)
                    .sort({ 'likes.length': -1, 'retweets.length': -1 })
                    .skip((page - 1) * limit)
                    .limit(limit)
                    .populate('userId', 'username fullName');
                break;
            
            case 'latest':
                tweets = await Tweet.find(query)
                    .sort({ createdAt: -1 })
                    .skip((page - 1) * limit)
                    .limit(limit)
                    .populate('userId', 'username fullName');
                break;
            
            case 'people':
                const users = await User.find({
                    $or: [
                        { username: { $regex: q, $options: 'i' } },
                        { fullName: { $regex: q, $options: 'i' } }
                    ]
                })
                .sort({ 'followers.length': -1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .select('-password');
                return res.json({ users });
            
            default:
                return res.status(400).json({ message: 'Invalid search type' });
        }

        res.json({ tweets });
    } catch (error) {
        console.error('Error searching:', error);
        res.status(500).json({ message: 'Error searching', error: error.message });
    }
});

// Trending Routes
app.get('/api/trending', authenticateToken, async (req, res) => {
    try {
        // Get tweets from the last 24 hours
        const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
        
        const tweets = await Tweet.find({
            createdAt: { $gte: yesterday },
            hashtags: { $exists: true, $ne: [] }
        });

        // Count hashtag occurrences
        const hashtagCounts = {};
        tweets.forEach(tweet => {
            tweet.hashtags.forEach(hashtag => {
                hashtagCounts[hashtag] = (hashtagCounts[hashtag] || 0) + 1;
            });
        });

        // Convert to array and sort
        const trending = Object.entries(hashtagCounts)
            .map(([hashtag, count]) => ({
                hashtag,
                tweetsCount: count,
                category: 'Women\'s Community' // You can add more specific categories later
            }))
            .sort((a, b) => b.tweetsCount - a.tweetsCount)
            .slice(0, 10);

        res.json({ topics: trending });
    } catch (error) {
        console.error('Error fetching trending topics:', error);
        res.status(500).json({ message: 'Error fetching trending topics', error: error.message });
    }
});

// Follow/Unfollow Routes
app.post('/api/users/:userId/follow', authenticateToken, async (req, res) => {
    try {
        if (req.user.userId === req.params.userId) {
            return res.status(400).json({ message: 'Cannot follow yourself' });
        }

        const userToFollow = await User.findById(req.params.userId);
        if (!userToFollow) {
            return res.status(404).json({ message: 'User not found' });
        }

        const currentUser = await User.findById(req.user.userId);
        
        const isFollowing = currentUser.following.includes(req.params.userId);
        
        if (isFollowing) {
            // Unfollow
            currentUser.following = currentUser.following.filter(id => id.toString() !== req.params.userId);
            userToFollow.followers = userToFollow.followers.filter(id => id.toString() !== req.user.userId);
        } else {
            // Follow
            currentUser.following.push(req.params.userId);
            userToFollow.followers.push(req.user.userId);
        }

        await Promise.all([currentUser.save(), userToFollow.save()]);

        res.json({ message: isFollowing ? 'Unfollowed successfully' : 'Followed successfully' });
    } catch (error) {
        console.error('Error following/unfollowing user:', error);
        res.status(500).json({ message: 'Error following/unfollowing user', error: error.message });
    }
});

// Delete Tweet
app.delete('/api/tweets/:tweetId', authenticateToken, async (req, res) => {
    try {
        const tweet = await Tweet.findById(req.params.tweetId);
        
        if (!tweet) {
            return res.status(404).json({ message: 'Tweet not found' });
        }

        // Check if the user is the owner of the tweet
        if (tweet.userId.toString() !== req.user.userId) {
            return res.status(403).json({ message: 'Not authorized to delete this tweet' });
        }

        await Tweet.findByIdAndDelete(req.params.tweetId);

        // Decrement user's tweet count
        await User.findByIdAndUpdate(req.user.userId, { $inc: { tweetsCount: -1 } });

        res.json({ message: 'Tweet deleted successfully' });
    } catch (error) {
        console.error('Error deleting tweet:', error);
        res.status(500).json({ message: 'Error deleting tweet', error: error.message });
    }
});

// Notification Routes
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const notifications = await Notification.find({ userId: req.user.userId })
            .sort({ createdAt: -1 })
            .populate('fromUser', 'username fullName')
            .populate('tweetId', 'content');

        res.json({ notifications });
    } catch (error) {
        console.error('Error fetching notifications:', error);
        res.status(500).json({ message: 'Error fetching notifications', error: error.message });
    }
});

app.post('/api/notifications/read', authenticateToken, async (req, res) => {
    try {
        await Notification.updateMany(
            { userId: req.user.userId },
            { $set: { read: true } }
        );
        res.json({ message: 'Notifications marked as read' });
    } catch (error) {
        console.error('Error marking notifications as read:', error);
        res.status(500).json({ message: 'Error marking notifications as read', error: error.message });
    }
});

// Serve index.html for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Start server
app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});
