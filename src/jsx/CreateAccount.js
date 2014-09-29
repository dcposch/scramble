/** @jsx React.DOM */

var React = require("react");
var Modal = require("./Modal");

module.exports = React.createClass({displayName: 'exports',
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
            React.DOM.div( {className:"form-horizontal"}, 
                React.DOM.div( {className:"text-center"}, 
                    React.DOM.em( {className:"js-generating-keys"}, keys ? "Done!" : "Generating PGP keys...")
                ),
                React.DOM.br(null),

                React.DOM.div( {className:"form-group"}, 
                    React.DOM.label( {className:"col-sm-3 control-label"}, "Username"),
                    React.DOM.div( {className:"col-sm-9"}, 
                        React.DOM.input( {type:"text", className:"form-control", ref:"createToken"} )
                    )
                ),

                React.DOM.div( {className:"form-group"}, 
                    React.DOM.label( {className:"col-sm-3 control-label"}, "Password"),
                    React.DOM.div( {className:"col-sm-9"}, 
                        React.DOM.input( {type:"password", className:"form-control", ref:"createPass"} )
                    )
                ),

                React.DOM.div( {className:"form-group"}, 
                    React.DOM.label( {className:"col-sm-3 control-label"}, "Confirm Password"),
                    React.DOM.div( {className:"col-sm-9"}, 
                        React.DOM.input( {type:"password", className:"form-control", ref:"confirmPass"} )
                    )
                ),

                React.DOM.p( {className:"help-block"}, "Please choose a strong passphrase and don't forget it.",React.DOM.br(null),
                    "The server won't know your passphrase or your private key. It can't read your mail.",React.DOM.br(null),
                    "This is sweet... but it also means that \"password reset\" is impossible!"
                ),

                React.DOM.div( {className:"form-group"}, 
                    React.DOM.label( {className:"col-sm-3 control-label"}, "Secondary Email"),
                    React.DOM.div( {className:"col-sm-9"}, 
                        React.DOM.input( {type:"text", className:"form-control", ref:"secondaryEmail"} )
                    )
                ),

                React.DOM.p( {className:"help-block"}, "If you give us your other email, we'll keep you updated on our progress.",React.DOM.br(null),
                    "We'll also remind you to check Scramble when you receive messages."
                )
            )
            );
        var footer = (
            React.DOM.div(null, 
                React.DOM.button( {type:"button", className:"btn btn-default", 'data-dismiss':"modal"}, "Close"),
                React.DOM.button( {type:"button", className:"btn btn-primary", 
                        disabled:!this.props.keys, 
                        onClick:this.handleCreateAccount}, 
                    "Create Account"
                )
            )
            );

        return (Modal( {title:title, body:body, footer:footer} ));
    }
});
