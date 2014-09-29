/** @jsx React.DOM */

var React = require("react");

module.exports = React.createClass({displayName: 'exports',
    componentDidMount: function() {
        $(this.getDOMNode()).modal();
    },

    componentWillUnmount: function() {
    },

    render: function(){
        var title = this.props.title;
        var body = this.props.body;
        var footer = this.props.footer;

        return (
        React.DOM.div( {className:"modal fade"}, 
            React.DOM.div( {className:"modal-dialog"}, 
                React.DOM.div( {className:"modal-content"}, 
                    React.DOM.div( {className:"modal-header"}, 
                        React.DOM.button( {type:"button", className:"close", 'data-dismiss':"modal", 'aria-hidden':"true"}, "×"),
                        React.DOM.h4( {className:"modal-title"}, title)
                    ),
                    React.DOM.div( {className:"modal-body"}, body),
                    React.DOM.div( {className:"modal-footer"}, footer)
                )
            )
        )
        );
    }
});
