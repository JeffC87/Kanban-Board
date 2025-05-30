import { JwtPayload, jwtDecode } from 'jwt-decode';

class AuthService {
  getProfile() {
    // TODO: return the decoded token
    
    const token = this.getToken();
    if (token) {  
      const decoded = jwtDecode<JwtPayload>(token);
      return decoded;
    }
    return null;
  }

  loggedIn() {
    // TODO: return a value that indicates if the user is logged in
    const token = this.getToken();
    if (token) {
      const decoded = jwtDecode<JwtPayload>(token);
      return !!decoded;
    }}
  
  isTokenExpired(token: string) {
    // TODO: return a value that indicates if the token is expired
    const decoded = jwtDecode<JwtPayload>(token);
    const currentTime = Date.now() / 1000; // Convert to seconds
    return decoded.exp ? decoded.exp < currentTime : false; 
  }

  getToken(): string | null {
    // TODO: return the token
    const token = localStorage.getItem('id_token');
    if (token&&!this.isTokenExpired(token)) {
      // Check if the token is expired 
      
      return token;
    }
    return null;  
  }

  login(idToken: string) {
    // TODO: set the token to localStorage
    localStorage.setItem('id_token', idToken);
    // TODO: redirect to the home page
    window.location.assign('/');
  }

  logout() {
    // TODO: remove the token from localStorage
    localStorage.removeItem('id_token');
    // TODO: redirect to the login page
    window.location.assign('/login');
  }
}

export default new AuthService();
