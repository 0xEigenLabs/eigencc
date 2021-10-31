//TODO  use redis in production
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
export let user_token : Map<string, session> = new Map();
}
