/** @jsx React.DOM */

var React = require("react");
module.exports = React.createClass({
    render: function() {
        return (
        <div className="container">
            <div className="row">
                <div className="form-signin center-block text-center" id="login">
                    <img src="./img/black_rubik.svg" className="logo-img" />
                    <h1 className="text-center">Scramble</h1>
                    <h3 className="text-center">Encrypted email for everyone</h3>
                    <hr className="invis" />
                    <input type="text" className="form-control" placeholder="Username" required="" autofocus="" id="token" name="token" />
                    <br />
                    <input type="password" className="form-control" placeholder="Passphrase" required="" id="pass" name="pass" />
                    <br />
                    <button className="btn btn-lg btn-default btn-block" type="submit" id="enterButton">Sign in</button>
                    <br />
                    <div className="error-signin text-danger"></div>
                    <div className="strike"><hr/><span>or</span></div>
                    <button className="btn btn-lg btn-primary btn-block" type="submit" id="generateButton">Create Account</button>
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
            <a href="https://github.com/dcposch/scramble">
                <img style="position: absolute; top: 0; right: 0; border: 0;" src="https://s3.amazonaws.com/github/ribbons/forkme_right_gray_6d6d6d.png" alt="Fork me on GitHub" />
            </a>
        </div>
        );
    }
});
