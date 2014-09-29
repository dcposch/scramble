/** @jsx React.DOM */

var React = require("react");
var ForkMe = require("./ForkMe");

module.exports = React.createClass({
    handleSignIn: function(){
        var username = this.refs.token.state.value;
        var password = this.refs.pass.state.value;
        this.props.onLogin(username, password);
    },
    handleCreateAccount: function(){
        this.props.onCreateAccount();
    },
    render: function() {
        return (
        <div className="container">
            <div className="row">
                <div className="form-signin center-block text-center">
                    <img src="./img/black_rubik.svg" className="logo-img" />
                    <h1 className="text-center">Scramble</h1>
                    <h3 className="text-center">Encrypted email for everyone</h3>
                    <hr className="invis" />
                    <input type="text" className="form-control" placeholder="Username" required="" autofocus="" ref="token" />
                    <br />
                    <input type="password" className="form-control" placeholder="Passphrase" required="" ref="pass" />
                    <br />
                    <button className="btn btn-lg btn-default btn-block" type="submit" onClick={this.handleSignIn}>Sign in</button>
                    <br />
                    <div className="error-signin text-danger"></div>
                    <div className="strike"><hr/><span>or</span></div>
                    <button className="btn btn-lg btn-primary btn-block" type="submit" onClick={this.handleCreateAccount}>Create Account</button>
                    <small>
                        <hr className="invis"/>
                        <p>
                            <a href="http://dcposch.github.com/scramble">How it works</a>
                        </p>
                        <p>
                            Questions? Feedback? Just testing a new account?<br/>
                            Send us a note! To: hello@scramble.io 
                        </p>    
                    </small>
                </div>
            </div>
            <ForkMe />
        </div>
        );
    }
});
