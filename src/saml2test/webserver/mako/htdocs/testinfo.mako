<%!

from aatest.check import STATUSCODE
from aatest import summation

def do_assertions(out):
  return summation.condition(out, True)
%>

<%!
from saml2 import SamlBase

def trace_output(trace):
    """

    """
    element = ["<h3>Trace output</h3>", "<ul>"]
    for event in trace:
        element.append("<li>%s" % event)
    element.append("</ul>")
    return "\n".join(element)
%>

<%!
from saml2.response import StatusResponse
from saml2 import SamlBase

def print_events(items):
    """

    """
    element = ["<h3>Events</h3>", "<ul>"]
    for event in items:
        if event.typ == 'outstanding':
            continue

        if event.typ == 'operation':
            element.append("<li>{}:{}:{}".format(event.timestamp, event.typ,
                                                 event.data.__name__))
        elif isinstance(event.data, StatusResponse):
            element.append("<li>{}:{}:".format(event.timestamp, event.typ))
            element.append("<textarea rows=\"20\" cols=\"80\">")
            element.append('{}'.format(event.data.response))
            element.append("</textarea>")
        elif isinstance(event.data, SamlBase):
            element.append("<li>{}:{}:".format(event.timestamp, event.typ))
            element.append("<textarea rows=\"20\" cols=\"80\">")
            element.append('{}'.format(event.data))
            element.append("</textarea>")
        else:
            element.append("<li>%s" % event)
    element.append("</ul>")
    return "\n".join(element)
%>

<%
def profile_output(pinfo):
    element = []
    for key, val in pinfo.items():
        element.append("<em>%s:</em> %s<br>" % (key,val))

    return "\n".join(element)
%>

<!DOCTYPE html>

<html>
  <head>
    <title>SAML2 IdP Test</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
      <link href="static/style.css" rel="stylesheet" media="all">

    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="../../assets/js/html5shiv.js"></script>
      <script src="../../assets/js/respond.min.js"></script>
    <![endif]-->
  </head>
  <body>

    <div class="container">
     <!-- Main component for a primary marketing message or call to action -->
        <h2>Test info</h2>
        ${profile_output(profile)}
        <hr>
        ${do_assertions(events)}
        <hr>
        ${trace_output(trace)}
        <hr>
        ${print_events(events)}
        <hr>
        <h3>Result</h3>${result}
    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>
  </body>
</html>