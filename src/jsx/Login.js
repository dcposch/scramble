/** @jsx React.DOM */

var React = require("react");
var ForkMe = require("./ForkMe");

module.exports = React.createClass({displayName: 'exports',
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
        React.DOM.div( {className:"container"}, 
            React.DOM.div( {className:"row"}, 
                React.DOM.div( {className:"form-signin center-block text-center"}, 
                    React.DOM.img( {src:"./img/black_rubik.svg", className:"logo-img"} ),
                    React.DOM.h1( {className:"text-center"}, "Scramble"),
                    React.DOM.h3( {className:"text-center"}, "Encrypted email for everyone"),
                    React.DOM.hr( {className:"invis"} ),
                    React.DOM.input( {type:"text", className:"form-control", placeholder:"Username", required:"", autofocus:"", ref:"token"} ),
                    React.DOM.br(null ),
                    React.DOM.input( {type:"password", className:"form-control", placeholder:"Passphrase", required:"", ref:"pass"} ),
                    React.DOM.br(null ),
                    React.DOM.button( {className:"btn btn-lg btn-default btn-block", type:"submit", onClick:this.handleSignIn}, "Sign in"),
                    React.DOM.br(null ),
                    React.DOM.div( {className:"error-signin text-danger"}),
                    React.DOM.div( {className:"strike"}, React.DOM.hr(null),React.DOM.span(null, "or")),
                    React.DOM.button( {className:"btn btn-lg btn-primary btn-block", type:"submit", onClick:this.handleCreateAccount}, "Create Account"),
                    React.DOM.small(null, 
                        React.DOM.hr( {className:"invis"}),
                        React.DOM.p(null, 
                            React.DOM.a( {href:"http://dcposch.github.com/scramble"}, "How it works")
                        ),
                        React.DOM.p(null, 
                            "Questions? Feedback? Just testing a new account?",React.DOM.br(null),
                            "Send us a note! To: hello@scramble.io" 
                        )    
                    )
                )
            ),
            ForkMe(null )
        )
        );
    }
});
