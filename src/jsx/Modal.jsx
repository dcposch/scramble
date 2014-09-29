/** @jsx React.DOM */

var React = require("react");

module.exports = React.createClass({
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
        <div className="modal fade">
            <div className="modal-dialog">
                <div className="modal-content">
                    <div className="modal-header">
                        <button type="button" className="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                        <h4 className="modal-title">{title}</h4>
                    </div>
                    <div className="modal-body">{body}</div>
                    <div className="modal-footer">{footer}</div>
                </div>
            </div>
        </div>
        );
    }
});
