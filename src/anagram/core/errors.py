"""The one error tree of Anagram.

Node side: `NodeError` and its subclasses carry an HTTP status. The node app
turns each one into a JSON response with that status.

Device side: `ClientError` is an error that the client shows to the person.
`LogMisbehaved` is a node answer that does not check out.

`FormatError` is a document or a field that does not match its format (both
sides).
"""


class NodeError(Exception):
    status = 400


class Unauthorized(NodeError):
    status = 401


class Forbidden(NodeError):
    status = 403


class NotFound(NodeError):
    status = 404


class Conflict(NodeError):
    status = 409


class Gone(NodeError):
    status = 410


class RateLimited(NodeError):
    status = 429


class FormatError(ValueError):
    """A document or field does not match its format."""


class ClientError(Exception):
    pass


class LogMisbehaved(ClientError):
    """The node returned a checkpoint, proof, or directory entry that does not check out."""
