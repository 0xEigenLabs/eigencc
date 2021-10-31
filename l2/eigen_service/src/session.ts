export module Session {
export class session {
    token: string
    expiry: number    
    issueTime: number
    constructor (t: string, e: number) {
        this.token = t;
        this.expiry = e;
        this.issueTime = Math.floor(Date.now() / 1000) 
    }

    isValid(this: session): boolean {
        let cur = Math.floor(Date.now() / 1000);
        console.log(this, cur)
        if (this.issueTime + this.expiry >= cur) {
            this.issueTime = cur;
            return true;
        }
        return false;
    }
}

//TODO use redis in production
let user_token : Map<string, session> = new Map();

export function check_token(key: string) {
    let sess = user_token.get(key);
    if (sess !== undefined && sess.isValid()) {
        user_token.set(key, sess)
        return sess.token;
    }
    user_token.delete(key)
    return null
}

export function add_token(key: string, sess: session) {
    user_token.set(key, sess)
}
}
