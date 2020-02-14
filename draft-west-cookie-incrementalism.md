---
title: Incrementally Better Cookies

abbrev: cookie-incrementalism
area: Applications and Real-Time
category: std
date: {DATE}
docname: draft-west-cookie-incrementalism-latest
ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi:
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  compact: yes
  comments: yes
  inline: yes
  tocdepth: 3

author:
 -
    ins: M. West
    name: Mike West
    organization: Google
    email: mkwst@google.com
    uri: https://www.mikewest.org/

normative:
  RFC2119:
  RFC6265bis: I-D.ietf-httpbis-rfc6265bis

informative:
  RFC7258:
  I-D.west-http-state-tokens:
  I-D.west-cookie-samesite-firstparty:
    target: https://tools.ietf.org/html/draft-west-cookie-samesite-firstparty-00
    title: First-Party Sets and SameSite Cookies
    date: May 7, 2019
    author:
    -
      ins: M. West
      name: Mike West
      organization: Google
  mixed-content:
    target: https://w3c.github.io/webappsec-mixed-content/
    title: Mixed Content
    author:
    -
      ins: M. West
      name: Mike West
      organization: Google
  pref-cookie:
    target: https://www.washingtonpost.com/news/the-switch/wp/2013/12/10/nsa-uses-google-cookies-to-pinpoint-targets-for-hacking/
    title: NSA uses Google cookies to pinpoint targets for hacking
    date: December 10, 2013
    author:
    -
      ins: A. Soltani
      name: Ashkan Soltani
    -
      ins: A. Peterson
      name: Andrea Peterson
    -
      ins: B. Gellman
      name: Barton Gellman
  first-party-set:
    target: https://mikewest.github.io/first-party-sets/
    title: First-Party Sets
    author:
    -
      ins: M. West
      name: Mike West
      organization: Google
  HTTP-Workshop-2019:
    target: https://github.com/HTTPWorkshop/workshop2019/wiki/Report
    title: "HTTP Workshop 2019: Report"
    date: April 2, 2019
    author:
    -
      ins: M. Nottingham
      name: Mark Nottingham
      organization: Fastly


--- abstract

This document proposes three changes to cookies inspired by the properties of
the HTTP State Tokens mechanism proposed in {{I-D.west-http-state-tokens}}.
First, cookies should be treated as `SameSite=Lax` by default. Second, cookies
that explicitly assert `SameSite=None` in order to enable cross-site delivery
should also be marked as `Secure`. Third, same-site should take the scheme of
the sites into account.


--- middle

# Introduction

The HTTP State Tokens proposal ({{I-D.west-http-state-tokens}}) aims to replace cookies with
a state management mechanism that has better security and privacy properties. That proposal is
somewhat aspirational: it's going to take a long time to come to agreement on the exact contours
of a cookie replacement, and an even longer time to actually do so.

While we're debating the details of a new state management primitive, it seems quite reasonable to
reevaluate some aspects of the existing primitive: cookies. When we can find consensus on some
aspect of HTTP State Tokens, we can apply those aspirations to cookies, driving incremental
improvements to state management in the status quo.

Based on conversations at {{HTTP-Workshop-2019}} and elsewhere, I'd suggest that we have something
like agreement on at least two principles:

1.  HTTP requests should not carry state along with cross-site requests by default (see Section 8.2
    of {{RFC6265bis}}).

2.  HTTP requests should not carry state over non-secure channels (see Section 8.3 of
    {{RFC6265bis}}, and {{RFC7258}}).

With those principles in mind, this document proposes three changes that seem possible to deploy in
the near-term. User agents should:

1.  Treat the lack of an explicit `SameSite` attribute as `SameSite=Lax`. That is, the `Set-Cookie`
    value `key=value` will produce a cookie equivalent to `key=value; SameSite=Lax`. Cookies that
    require cross-site delivery can explicitly opt-into such behavior by asserting `SameSite=None`
    when creating a cookie.

    This is spelled out in more detail in {{lax-default}}.

2.  Require the `Secure` attribute to be set for any cookie which asserts `SameSite=None` (similar
    conceptually to the behavior for the `__Secure-` prefix). That is, the `Set-Cookie` value
    `key=value; SameSite=None; Secure` will be accepted, while `key=value; SameSite=None` will be
    rejected.

    This is spelled out in more detail in {{require-secure}}.

3. Ensure the scheme, as well as the registrable domain, of the
   "site for cookies" and request match when making a same-site decision.
   That is, "http://site.example" and "https://site.example" should be
   considered cross-site

   This is spelled out in more detail in {{#schemeful-samesite}}.


# Conventions and Definitions

## Conformance

{::boilerplate bcp14}

## Syntax

This document adjusts some syntax from {{RFC6265bis}}, and in doing so, relies upon the Augmented
Backus-Naur Form (ABNF) notation of {{!RFC5234}}.


# Monkey-Patches against RFC6265bis

## "Lax" by Default {#lax-default}

The processing algorithm in Section 5.3.7 of {{RFC6265bis}} treats the absence of a `SameSite`
attribute in a `Set-Cookie` header as equivalent to the presence of `SameSite=None`. Cookies are
therefore available for cross-site delivery by default, and developers may opt-into more security by
setting some other value explicitly. Ideally, we'd invert that such that developers who accepted the
risks of cross-site delivery (see Section 8.2 of {{RFC6265bis}}) could opt into them, while
developers who didn't make any explicit choice would be protected by default.

We could accomplish this goal by first altering the processing algorithm, replacing the current step
1:

~~~
1.  Let "enforcement" be "None".
~~~

with the following two steps:

~~~
1.  Let "enforcement" be "Lax".

2.  If cookie-av's attribute-value is a case-insensitive
    match for "None", set "enforcement" to "None".
~~~

And then by, altering step 13 of the cookie storage model (Section 5.4 of {{RFC6265bis}}) from:

~~~
13. If the cookie-attribute-list contains an attribute
    with an attribute-name of "SameSite", set the cookie's
    same-site-flag to attribute-value (i.e. either "Strict",
    "Lax", or "None"). Otherwise, set the cookie's
    same-site-flag to "None".
~~~

to:

~~~
13. If the cookie-attribute-list contains an attribute
    with an attribute-name of "SameSite", set the
    cookie's same-site-flag to attribute-value. Otherwise,
    set the cookie's same-site-flag to "Lax".
~~~

This would have the effect of mapping the default behavior in the absence of an explicit `SameSite`
attribute, as well as the presence of any unknown `SameSite` value, to the "Lax" behavior,
protecting developers by making cross-site delivery an explicit choice, as opposed to an implicit
default.


## Requiring "Secure" for "SameSite=None" {#require-secure}

Cookies sent over plaintext HTTP are visible to anyone on the network. As section 8.3 of
{{RFC6265bis}} points out, this visibility exposes substantial amounts of data to network attackers.
We know, for example, that long-lived and stable cookies have enabled pervasive monitoring
{{RFC7258}} in the past (see Google's PREF cookie {{pref-cookie}}), and we know that a secure
transport layer provides significant confidentiality protections against this kind of attack.

We can, to a reasonable extent, mitigate this threat by ensuring that cookies intended for
cross-site delivery (and therefore likely to be more prevalent on the wire than cookies scoped down
to same-site requests) require secure transport.

That is, we can require that any cookie which asserts `SameSite=None` must also assert the `Secure`
attribute (Section 4.1.2.5 of {{RFC6265bis}}) by altering the storage model defined in Section 5.4 of
{{RFC6265bis}}, inserting the following step after the existing step 14:

~~~
15. If the cookie's "same-site-flag" is "None", abort
    these steps and ignore the cookie entirely unless
    the cookie's secure-only-flag is true.
~~~

This is conceptually similar to the requirements put into place for the `__Secure-` prefix (Section
4.1.3.1 of {{RFC6265bis}}).

## Schemeful Same-Site {#schemeful-samesite}

By using the scheme, as well as the registrable domain, SameSite can help to
protect https origins against a network attacker that is impersonating an http
origin with the same registrable domain. Further increasing its CSRF
protections. To do so we need to modify a number of things:

First change the definition of "site for cookies" from a registrable domain to
an origin. In the places where a we return an empty string for a non-existent
"site for cookies" we should instead return an origin set to a freshly
generated globally unique identifier.

Then replace the same-site calculation algorithm with the following
~~~
Two origins, A and B, are considered same-site if the following algorithm returns true:
1.  If A and B are both scheme/host/port triples then

    1.  If A's scheme does not equal B's scheme, return false.

    2.  Let hostA be A's host, and hostB be B's host.

        1.  If hostA equals hostB and hostA's registrable domain is null, return true.

        2.  If hostA's registrable domain equals hostB's registrable domain and is non-null, return true.

2.  If A and B are both the same globally unique identifier, return true.

3.  Return false.

Note: The port component of the origins is not considered.

A request is "same-site" if its target's URI's origin
is same-site with the request's client's "site for cookies", or if the
request has no client. The request is otherwise "cross-site".
~~~

Next we'll modify the algorithm which returns same-site or cross-site for a
given request.
Replace lines 3 and 4 with
~~~
3.  Let `target` be the origin of `request`'s current url.

4.  If `site` is same-site with `target`, return `same-site`.
~~~

Since we're now looking at scheme and would like WebSockets to continue to be
able to use cookies let's add the following note directly after the above algorithm.

~~~
Note: The request's URL when establishing a WebSockets connection {{RFC6455}}
has scheme "http" or "https", rather than "ws" or "wss". See {{FETCH}} which
maps schemes when constructing the request. This allows same-site cookies to be
sent with WebSockets.
~~~

Finally, since we're citing RFC6455 it should be added to the informative section.


# Security and Privacy Considerations

## CSRF

`SameSite` is a reasonably robust defense against some classes of cross-site request forgery
attacks, as described in Section 8.8.1 of {{RFC6265bis}}, but developers need to opt-into its
protections in order for them to have any effect. That is, developers are vulnerable to CSRF
attacks by default, and must do some work to shift themselves into a more defensible position.

The change proposed in {{lax-default}} would invert that requirement, placing the burden on the
small number of developers who are building services that require state in cross-site requests.
Those developers would be empowered to opt-into the status quo's less-secure model, while developers
who don't intend for their projects to be embedded in cross-site contexts are protected by default.


## Secure Transport

As discussed in Section 8.3 of {{RFC6265bis}}, cookies delivered over plaintext channels are
exposed to intermediaries, and thereby enable pervasive monitoring {{RFC7258}}. The change proposed
in {{require-secure}} above would set secure transport as a baseline requirement for all stateful
cross-site requests, thereby reducing the risk that these cookies can be cataloged or modified by
network attackers.

Requiring secure transport for cookies intended for cross-site usage has the exciting secondary
effect of increasing pressure on entities that produce embeddable content to migrate their
products to HTTPS. That has security benefits for those third-party products themselves, but also
has the effect of removing the potential of mixed content ({{mixed-content}}) as a blocker to
first-party migration to HTTPS.

Note that in the long term, it seems quite reasonable to take the additional step of requiring the
`Secure` attribute for all cookies, regardless of their `SameSite` value. That would have more
substantial impact on pervasive monitoring and network attackers generally. This document's proposal
limits itself to `SameSite=None` because that seems like a low-hanging, high-value change that's
deployable in the near term. User agents are encouraged to find additional subsets for which
`Secure` can be required.


## Tracking

The proposals in this document do not in themselves mitigate the privacy risks described in Section
7.1 of {{RFC6265bis}}. Entities who wish to use cookies to track user activity from cross-site
contexts can continue to do so by setting cookies that declare themselves as `SameSite=None`.

Requiring that explicit declaration, however, gives user agents the ability to easily distinguish
cookies used for stateful cross-site requests from those with narrower scope. After the change
proposed in {{lax-default}}, only those cookies that make an explicit `SameSite=None` declaration
can be directly used for cross-site tracking. It may make sense for user agents to use that
information to give users different controls for these cookies, or to apply different policies for
expiration and delivery.


# Implementation Considerations

## Sequencing

The steps described in this document don't need to be taken at the same time. It's quite possible
that it will be less disruptive to deploy `SameSite=Lax` as a default first, then to require the
`Secure` attribute for any explicitly `SameSite=None` cookie as a subsequent step, and then
deploying schemeful same-site in a final step.

User agents are encouraged to adopt these recommendations in whatever order they believe will lead
to the widest, most expedient deployment.


## Deployment

It's possible that a middle-ground between `SameSite=Lax` and `SameSite=None` could be a better
balance between doing what developers want by default, and mitigating CSRF by default.
{{I-D.west-cookie-samesite-firstparty}} explores the possibility of integrating First-Party Sets
{{first-party-set}} with the `SameSite` attribute in order to allow entities that shard themselves
across multiple registrable domains to maintain stateful communication between them (to support
single-sign on, for example).

It's possible that user agents who support First-Party Sets could reduce the deployment overhead
for developers, and increase the robustness of a site's CSRF defense for
cross-site-but-not-cross-party cookies by defaulting to something like that document's
`FirstPartyLax` instead of `Lax`.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

Conversations with a number of folks at 2019's HTTP Workshop helped me clarify my thinking around
the incremental improvements we can make to cookies. In particular, Martin Thomson and Anne van
Kesteren provided insightful feedback.
