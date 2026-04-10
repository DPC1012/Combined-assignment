const jwt = require('jsonwebtoken');
const z = require('zod');
const jwtPassword = 'secret';

/**
 * Generates a "Short-Lived" JWT that expires in 1 minute.
 * * @param {string} username - The user's email.
 * @returns {string} A JWT that will be invalid after 60 seconds.
 */
const signSchema = z.object({
    username: z.string().email()
})
function signShortLivedToken(username) {
    // Your code here
    const {data, success} = signSchema.safeParse({username});
    if(!success)return null;
    return jwt.sign({username: data.username}, jwtPassword, {expiresIn: "1m"});
}

/**
 * Checks if a token is still valid or has expired.
 * * @param {string} token - The JWT string.
 * @returns {string} Returns "valid", "expired", or "invalid".
 */
function checkTokenStatus(token) {
    // Your code here
    if(!token)return "invalid";
    try
    {
        const verifyToken = jwt.verify(token,jwtPassword);
        return "valid";
    }
    catch(error)
    {
        if(error.name === "TokenExpiredError")return "expired";
        else return "invalid";
    }
}

module.exports = {
    signShortLivedToken,
    checkTokenStatus,
    jwtPassword
}
