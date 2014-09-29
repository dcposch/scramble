/** @jsx React.DOM */

var React = require("react");
var Modal = require("./Modal");

module.exports = React.createClass({
    handleCreateAccount: function() {
        var token = this.refs.createToken.state.value;
        var pass = this.refs.createPass.state.value;
        var pass2 = this.refs.confirmPass.state.value;
        var secondaryEmail = this.refs.secondaryEmail.state.value;
        if(pass !== pass2){
            alert("Passwords must match");
            return;
        }

        var keys = this.props.keys;
        if(!keys){
            return;
        }

        this.props.onCreateAccount(token, pass, secondaryEmail, keys);
    },

    render: function() {
        var keys = this.props.keys;

        var title = "Welcome to Scramble!";
        var body = (
            <div className="form-horizontal">
                <div className="text-center">
                    <em className="js-generating-keys">{keys ? "Done!" : "Generating PGP keys..."}</em>
                </div>
                <br/>

                <div className="form-group">
                    <label className="col-sm-3 control-label">Username</label>
                    <div className="col-sm-9">
                        <input type="text" className="form-control" ref="createToken" />
                    </div>
                </div>

                <div className="form-group">
                    <label className="col-sm-3 control-label">Password</label>
                    <div className="col-sm-9">
                        <input type="password" className="form-control" ref="createPass" />
                    </div>
                </div>

                <div className="form-group">
                    <label className="col-sm-3 control-label">Confirm Password</label>
                    <div className="col-sm-9">
                        <input type="password" className="form-control" ref="confirmPass" />
                    </div>
                </div>

                <p className="help-block">Please choose a strong passphrase and don't forget it.<br/>
                    The server won't know your passphrase or your private key. It can't read your mail.<br/>
                    This is sweet... but it also means that "password reset" is impossible!
                </p>

                <div className="form-group">
                    <label className="col-sm-3 control-label">Secondary Email</label>
                    <div className="col-sm-9">
                        <input type="text" className="form-control" ref="secondaryEmail" />
                    </div>
                </div>

                <p className="help-block">If you give us your other email, we'll keep you updated on our progress.<br/>
                    We'll also remind you to check Scramble when you receive messages.
                </p>
            </div>
            );
        var footer = (
            <div>
                <button type="button" className="btn btn-default" data-dismiss="modal">Close</button>
                <button type="button" className="btn btn-primary" 
                        disabled={!this.props.keys} 
                        onClick={this.handleCreateAccount}>
                    Create Account
                </button>
            </div>
            );

        return (<Modal title={title} body={body} footer={footer} />);
    }
});

