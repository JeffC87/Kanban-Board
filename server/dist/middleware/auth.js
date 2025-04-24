import jwt from 'jsonwebtoken';
export const authenticateToken = (req, res, next) => {
    // TODO: verify the token exists and add the user data to the request object
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        res.sendStatus(401); // Unauthorized
        return;
    }
    jwt.verify(token, process.env.JWT_SECRET || '', (err, decoded) => {
        if (err) {
            res.sendStatus(403); // Forbidden
            return;
        }
        req.user = decoded;
        next();
    });
};
