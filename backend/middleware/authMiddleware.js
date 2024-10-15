
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const authMiddleware = async (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    
   
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    try {
     
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await User.findById(decoded.user.id).select('-password');
        
   
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

       
        req.user = user;
        next(); 
    } catch (err) {
        console.error('Middleware error:', err.message); 
        res.status(401).json({ message: 'Token is not valid' });
    }
};

module.exports = authMiddleware;
