/** @jsx React.DOM */

var imgStyle = {
    "position": "absolute", 
    "top": 0, 
    "right": 0, 
    "border": 0
};
var imgUrl = "https://s3.amazonaws.com/github/ribbons/forkme_right_gray_6d6d6d.png";

var React = require("react");
module.exports = React.createClass({
    render: function() {
        return (
            <a href="https://github.com/dcposch/scramble">
                <img style={imgStyle}
                    src={imgUrl}
                    alt="Fork me on GitHub" />
            </a>
        );
    }
});

