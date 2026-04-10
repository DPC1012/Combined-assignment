const jwt = require('jsonwebtoken');
const z = require('zod');
const jwtPassword = 'secret_key';

/**
 * Generates a JWT that includes a user's role (admin or guest).
 * * @param {string} username - The user's email.
 * @param {string} role - The user's role, must be either 'admin' or 'guest'.
 * @returns {string|null} A JWT if role is valid; otherwise null.
 */
const signSchema = z.object({
    username: z.string().email(),
    role: z.enum(["admin","guest"])
})
function signJwtWithRole(username, role) {
    // Your code here
    const {data, success} = signSchema.safeParse({username,role});
    if(!success)return null;
    try{
        const token = jwt.sign({username: data.username,role: data.role}, jwtPassword);
    return token;
    }
    catch(e)
    {
        return null;
    }
}

/**
 * Checks if a given token belongs to an admin.
 * * @param {string} token - The JWT string.
 * @returns {boolean} True if the role in the payload is 'admin', false otherwise.
 */
function isAdmin(token) {
    // Your code here
    if(!token || token.trim() === "")return false;
    try{
        const verifyToken = jwt.verify(token, jwtPassword);
        if(!verifyToken)return false;
        else if(verifyToken.role === "admin")return true;
        else return false
    }
    catch(e) {
        return false;
    }
}

module.exports = {
    signJwtWithRole,
    isAdmin,
    jwtPassword,
};