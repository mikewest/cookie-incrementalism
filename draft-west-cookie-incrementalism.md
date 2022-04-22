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
  HTML:
    title: HTML
    target: https://html.spec.whatwg.org/
  RFC2119:
  RFC6265bis: I-D.ietf-httpbis-rfc6265bis

informative:
  RFC7258:
  I-D.thomson-http-omnomnom:
  I-D.west-http-state-tokens:
  I-D.west-cookie-samesite-firstparty:
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
  cookies-over-http-bad:
    title: Cookies over HTTP Bad
    target: https://github.com/mikewest/cookies-over-http-bad
    date: April 6, 2018
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

This document proposes a few changes to cookies inspired by the properties of
the HTTP State Tokens mechanism proposed in {{I-D.west-http-state-tokens}}.
First, cookies should be treated as `SameSite=Lax` by default. Second, cookies
that explicitly assert `SameSite=None` in order to enable cross-site delivery
should also be marked as `Secure`. Third, same-site should take the scheme of
the sites into account. Fourth, cookies should respect schemes. Fifth, cookies
associated with non-secure schemes should be removed at the end of a user's
session. Sixth, the definition of a session should be tightened.


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
like agreement on at least three principles:

1.  HTTP requests should not carry state along with cross-site requests by default (see Section 8.2
    of {{RFC6265bis}}).

2.  HTTP requests should not carry state over non-secure channels (see Section 8.3 of
    {{RFC6265bis}}, and {{RFC7258}}).

3.  Non-secure channels should not be able to infuence the state of securely-transported content
    (see Sections 8.3, 8.5, and 8.6 of {{RFC6265bis}}).

With those principles in mind, this document proposes a few changes that seem possible to deploy in
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

3. Require both the scheme and registrable domain of a request's client's "site for cookies"
   to match the target URL when deciding whether a given request is considered same-site.
   That is, a request initiated from "http://site.example" to "https://site.example" should be
   considered cross-site.

   This is spelled out in more detail in {{schemeful-samesite}}.

4. Separate cookies by origin. That is, a given cookie set from
   `http://example.com/` should be considered distinct from the same
   cookie set from `https://example.com/` which should again be
   considered distinct from the same cookie set from
   `https://example.com:123/`, preventing any origin from influencing the
   state of any other.

   This is spelled out in more detail in {{origin-bound-cookies}}.

5. Evict non-secure cookies when a user's session on a non-secure site ends, thereby reducing the
   timespan over which a user broadcasts a stable identifier to the network.

   This is spelled out in more detail in {{evict-nonsecure}}.

6. Tighten the definition of a user's "session" with heuristics that better represent users'
   expectations.

   This is spelled out in more detail in {{session-lifetime}}.


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
1.  Let "enforcement" be "Default".

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
    with an attribute-name of "SameSite" and an
    attribute-value of "Strict", "Lax", or "None", set the
    cookie's same-site-flag to attribute-value. Otherwise,
    set the cookie's same-site-flag to "Default".
~~~

And finally by altering the fifth bullet point of step 1 of the cookie-string construction algorithm
in Section 5.5 of {{RFC6265bis}} from:

~~~
 *  If the cookie's same-site-flag is not "None", and the HTTP
    request is cross-site (as defined in Section 5.2) then exclude
    the cookie unless all of the following statements hold:

    1.  The same-site-flag is "Lax"

    2.  The HTTP request's method is "safe".

    3.  The HTTP request's target browsing context is a top-level
        browsing context.
~~~

to:

~~~
 *  If the cookie's same-site-flag is not "None", and the HTTP
    request is cross-site (as defined in Section 5.2) then exclude
    the cookie unless all of the following statements hold:

    1.  The same-site-flag is "Lax" or "Default".

    2.  The HTTP request's method is "safe".

    3.  The HTTP request's target browsing context is a top-level
        browsing context.
~~~

This would have the effect of mapping the default behavior in the absence of an explicit `SameSite`
attribute, as well as the presence of any unknown `SameSite` value, to the "Lax" behavior,
protecting developers by making cross-site delivery an explicit choice, as opposed to an implicit
default.


### "Lax-Allowing-Unsafe" Enforcement {#lax-allowing-unsafe}

The "Lax" enforcement mode described in Section 5.3.7.1 of {{RFC6265bis}} allows a cookie to be sent
along with cross-site requests if and only if they are top-level navigations with a "safe" HTTP
method. Implementation experience shows that this is difficult to apply across the board, and it may
be reasonable to temporarily carve out cases in which some cookies that rely on today's default
behavior can continue to be delivered as the default is shifted to "Lax" enforcement.

One such carveout, described in this section, accommodates certain cases in which it may be
desirable for a cookie to be excluded from non-top-level cross-site requests, but to be sent with
all top-level navigations regardless of HTTP request method.

For example, a login flow may involve a cross-site top-level POST request to an endpoint which
expects a cookie with login information. For such a cookie, "Lax" enforcement is not appropriate, as
it would cause the cookie to be excluded due to the unsafe HTTP request method. On the other hand,
"None" enforcement would allow the cookie to be sent with all cross-site requests. For a cookie
containing potentially sensitive login information, this may not be desirable.

In order to retain some of the protections of "Lax" enforcement (as compared to "None") while still
allowing cookies to be sent cross-site with unsafe top-level requests, user agents may choose to
provide an intermediate "Lax-allowing-unsafe" enforcement mode. A cookie whose enforcement mode is
"Lax-allowing-unsafe" will be sent along with a cross-site request if and only if it is a top-level
request, regardless of request method.

User agents may choose to apply this enforcement mode instead of "Lax" enforcement, but only in a
limited or restricted fashion. Such restrictions may include applying "Lax-allowing-unsafe" only to
cookies that did not explicitly specify `SameSite=Lax` (i.e., those whose same-site-flag was set to
"Default" by default) with creation-time more recent than a duration of the user agent's choosing (2
minutes seems reasonable).

This is done by further modifying the previously mentioned fifth bullet point of step 1 of the
cookie-string construction algorithm in Section 5.5 of {{RFC6265bis}} from:

~~~
 *  If the cookie's same-site-flag is not "None", and the HTTP
    request is cross-site (as defined in Section 5.2) then exclude
    the cookie unless all of the following statements hold:

    1.  The same-site-flag is "Lax" or "Default".

    2.  The HTTP request's method is "safe".

    3.  The HTTP request's target browsing context is a top-level
        browsing context.
~~~

to:

~~~
 *  If the cookie's same-site-flag is not "None", and the HTTP
    request is cross-site (as defined in Section 5.2) then exclude
    the cookie unless all of the following statements hold:

    1.  The same-site-flag is "Lax" or "Default".

    2.  The HTTP request's method is "safe", or the cookie meets
        the user agent's requirements for being granted
        "Lax-allowing-unsafe" enforcement.

    3.  The HTTP request's target browsing context is a top-level
        browsing context.
~~~

As a more permissive variant of "Lax" mode, "Lax-allowing-unsafe" mode necessarily provides fewer
protections against CSRF.  Ultimately, the provision of such an enforcement mode should be seen as a
temporary measure to ease adoption of "Lax" enforcement by default.


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

By considering the scheme as well as the registrable domain when determining whether a
given request is "same-site", the `SameSite` attribute can protect secure origins from CSRF
attacks initiated by a network attacker that can forge requests from a non-secure origin on
the same registrable domain. To do so we need to modify a number of things:

First change the definition of "site for cookies" from a registrable domain to
an origin. In the places where a we return an empty string for a non-existent
"site for cookies" we should instead return an origin set to a freshly
generated globally unique identifier.
Then replace the same-site calculation algorithm with the following:

~~~
Two origins, A and B, are considered same-site if the following algorithm returns true:
1.  If A and B are both scheme/host/port triples then

    1.  If A's scheme does not equal B's scheme, return false.

    2.  Let hostA be A's host, and hostB be B's host.

    3.  If hostA equals hostB and hostA's registrable domain is null, return true.

    4.  If hostA's registrable domain equals hostB's registrable domain and is non-null, return true.

2.  If A and B are both the same globally unique identifier, return true.

3.  Return false.

Note: The port component of the origins is not considered.

A request is "same-site" if its target's URI's origin
is same-site with the request's client's "site for cookies", or if the
request has no client. The request is otherwise "cross-site".
~~~

Now that we have a new algorithm, we can update any comparision of two sites
from "have the same registrable domain" (or "is an exact match for") to say
"is same-site".

Note: The request's URL when establishing a WebSockets connection has scheme "http" or "https", rather than "ws" or "wss". FETCH maps schemes when constructing the request. This mapping allows same-site cookies to be sent with WebSockets.

## Origin-Bound Cookies {#origin-bound-cookies}

Cookies are one of the few components of the web platform that are not
scoped to the origin by default. This difference in scoping means that
cookies have weaken confidentiality and integrity compared with other
storage APIs on the web platform.

Examples:

1. `https://somesite.com` sets a simple cookie, `secret=123456`,
    which contains private information about a user. Information that
    an attacker wishes to learn. To do so the attacker
    man-in-the-middles the user, and then tricks them into visiting
    `http://somesite.com` (note the insecure scheme). When the user
    visits that page their browser will send the `secret` cookie and
    the attacker can see it.

2. Similarly, if the attacker has somehow compromised a service running
    on a different port on the same server, let's say port 345, as
    `https://somesite.com` then they could trick the user into visiting
    `https://somesite.com:345`, the user's browser will send the `secret`
    cookie, and once again the attacker can see it.

Even more, through the same techniques, an attacker can also modify
a user's cookies, sending a `Set-Cookie` field instead of simply
eavesdropping.

All of these examples are possible because cookies by default do not
care about the scheme or port of their connection. As long as the host
matches the cookie will be accessible.

Some of these shortcomings can be alleviated: the `Secure` attribute
scopes a cookie to only be accesible on secure schemes and the cookie
prefixes, `__Secure-` and `__Host-`, can tighten that boundary more.
While these solve the problem shown in the first example, they are all
opt-in and are not always used. They also do nothing to help solve
the port problem shown in the example two. In fact, there are currently
no mechanisms that can strengthen cookies' port boundaries.

These weaknesses in cookies gives network attackers the ability to spy
upon users and influence otherwise secured traffic by modifying users'
state as Sections 8.5 and 8.6 of {{RFC6265bis}} point out.

We should remedy this defect by storing both a "scheme" and "port"
component along with the cookie, and use those components in cookies'
matching algorithms to ensure that a cookie is only sent to the origin
that originally set it, thus keeping origins' state separate by
default.

Example: 

* `https://example.com` sets a cookie `foo=https` and `http://example.com`
   sets a cookie `foo=http`. Previously this would result in one of
   the cookies being overwritten by the other. Now, they're considered
   seperate and when visiting each site users could see their
   respective cookie. The same holds true for `https://example.com` and
   `https://example.com:444`, each is a different origin and thus have
   their own cookies.

It's possible that a site operator purposefully wants some cookies to
be accessible across port boundaries. Because this would weaken the
origin boundary, by increasing the cookie's scope, we'd want this to be
an opt-in mechanism. Helpfully there is already an attribute that
increases a cookie's scope: the `Domain` attribute. We can modify the
`Domain` attribute slightly such that it not only allows cookies to be
accessible by different hosts but also by different ports than the
origin's that set it. For convenience we'll call any cookie with a
`Domain` attribute a "domain cookie".

Example:

* A corporate network, `https://corp.example`, has various services
   each running on their own port. Those services share use of a token
   which allows users to use the services. To get a token a user logs
   in on `https://corp.example/login/` which creates the cookie
   `IDToken=a1b2bc3`. Next, to file an expense, the user needs to
   visit `https://corp.example:8443`, but when they do the IDToken
   isn't sent because the ports differ (443 vs 8443) and the user is
   denied access. To remedy this, the IDToken can have the `Domain` 
   attribute added to it: `IDToken=a1b2d3; Domain=corp.example`.
   Now when the user visits `https://corp.example:8443` the token
   is sent and access is granted as expected.

Because any domain cookie is now exposed to multiple origins it means
a cookie created by one origin can be overwritten by another origin. 

Examples:

1. `https://example.com:123` sets a cookie: `Set-Cookie: 
    foo=domaincookie; Domain=example.com`. The user then visits 
    `https://example.com:456` which sets the same cookie. This second
    cookie would match the first and then overwrite it. 
2. `https://example.com:123` sets a cookie 
    `Set-Cookie: foo=domaincookie; Domain=example.com`. The user then
    visits `https://example.com:456` which sets `Set-Cookie: 
    foo=origincookie`. The second cookie would match the first an
    overwrite it.
    
Also, because domain cookies are less trusted due to their wider scope,
we'll want to avoid allowing them to shadow non-domain cookies by
disallowing domain cookies from co-exiting or overwriting a matching
non-domain cookie. This is a departure from the status quo in which
this shadowing behavior is specifically allowed.

Example:

* `https://example.com:456` sets a non-domain cookie`Set-Cookie:
   foo=origincookie`. The user then visits `https://example.com:123`
   which tries to set a domain cookie `Set-Cookie: foo=domaincookie;
   Domain=example.com` This set fails because a domain cookie should
   never overwrite a matching non-domain cookie.

Finally, we don't ever want to allow a cookie to pass between schemes,
given the huge security differences between them. So there should be no
way for a server to specify that a given cookie should be sent to a
different scheme.

How we accomplish this is as follows:

First, add the concept of port matching which helps to simplify checking
if a cookie would match a port value. We can do that by adding a new
section under 5.1 (this new section depends on the modification to 5.4
below)

~~~
5.1.5 Port matching 

An integer port-matches a given cookie if any of the following
conditions are true:
  1. The integer exactly matches the cookie's port value.

  2. The cookie's host-only-flag is false.
~~~

We also want to add a sub-algorithm to protect origin cookies from being
overwritten/shadowed by domain cookies. This'll be run during the
creation of new cookies in a later step.

~~~
5.1.6 New Cookie does not Shadow or Overwrite Origin-only Cookies

This algorithm protects any existing origin-only cookies from being
overwritten or shadowed by a new cookie ("new-cookie") with the Domain
attribute and is as follows:

1.  If the new-cookie's host-only-flag is true, then return true.
2.  If the new-cookie's host-only-flag is false, then return false
    if the cookie store contains at least one cookie ("equiv-cookie")
    that meets all of the following criteria: 
    
    1.  Equiv-cookie's name and scheme are equal to new-cookie's name
        and scheme.
    2.  Equiv-cookie's host-only-flag is true.
    3.  Equiv-cookie's domain domain-matches the domain of new-cookie.
        (Note: this is an asymmetrical comparison) 
    
    Otherwise return true

Notice the asymmetric comparison during the domain-matching. It can be
helpful to think of domain-matching as: "A domain-matches B when A is
equivalent to or a sub-domain of B". Since a cookie with the Domain
attribute is sent to all hosts that are equivalent to or a sub-domain
of its Domain's value, this asymmetric comparison prevents a cookie
with the Domain attribute from being set when it would be sent to any
host that also contains an origin-only cookie.

Note: This comparison intentionally ignores the "path" component. The
intent is to protect a more tightly scoped origin bound cookie across
the entire origin.

Example: https://landing.site.example sets a cookie `Set-Cookie:
a=origincookie`. The user then visits https://account.site.example
which tries to set a cookie `Set-Cookie: a=domaincookie;
Domain=site.example`. The second cookie would fail to be set because
the cookie would shadow "a=origincookie".
~~~

Next, alter the storage model in Section 5.4 of {{RFC6265bis}} by
adding "scheme" and "port" to the list of fields the user agent stores
about each cookie, and setting them. Also, let's refer to the newly
created cookie by "new-cookie" by altering step 3 of the algorithm
from:

~~~
3.  Create a new cookie with name cookie-name, value cookie-value. Set
    the creation-time and the last-access-time to the current date and
    time.
~~~

to: 

~~~
3.  Create a new cookie ("new-cookie") with name cookie-name, value
    cookie-value. Set the creation-time and the last-access-time to the
    current date and time, set the scheme to the request-uri's origin's
    scheme component, and set the port to the request-uri's origin's
    port component.
~~~

References to the cookie should also be updated to use "new-cookie" in
steps 3-20 as required.

To prevent "domain cookies" from shadowing "origin cookies" we alter
step 13 from

~~~
13. If the cookie's secure-only-flag is false, and the scheme component
    of request-uri does not denote a "secure" protocol, then abort
    these steps and ignore the cookie entirely if the cookie store
    contains one or more cookies that meet all of the following
    criteria:

    1. Their name matches the name of the newly-created cookie.

    2. Their secure-only-flag is true.

    3. Their domain domain-matches the domain of the newly-created
       cookie, or vice-versa.

    4. The path of the newly-created cookie path-matches the path of
       the existing cookie.

    Note: The path comparison is not symmetric, ensuring only that a
    newly-created, non-secure cookie does not overlay an existing
    secure cookie, providing some mitigation against cookie-fixing
    attacks.  That is, given an existing secure cookie named 'a' with a
    path of '/login', a non-secure cookie named 'a' could be set for a
    path of '/' or '/foo', but not for a path of '/login' or
    '/login/en'.
~~~

to:

~~~
13. If the algorithm specified by 5.1.6 New Cookie does not Shadow or
    Overwrite Origin-only Cookies returns false, then abort these steps
    and ignore the cookie entirely.
~~~

Note: Because all cookies are now scoped by scheme it is unnecessary to
protect a secure scheme's cookies from an insecure scheme's cookies and
thus we can drop the related checks in the original step 13.

To incorporate the new fields and "domain cookie" port matching, alter
step 19 of the same algorithm from

~~~
19. If the cookie store contains a cookie with the same name, domain,
    host-only-flag, and path as the newly-created cookie:

    1. Let old-cookie be the existing cookie with the same name,
       domain, host-only-flag, and path as the newly-created cookie.
       (Notice that this algorithm maintains the invariant that there
       is at most one such cookie.)

    2. If the newly-created cookie was received from a "non-HTTP" API
       and the old-cookie's http-only-flag is true, abort these steps
       and ignore the newly created cookie entirely.

    3. Update the creation-time of the newly-created cookie to match
       the creation-time of the old-cookie.

    4. Remove the old-cookie from the cookie store.
~~~

to:

~~~
19. If the cookie store contains a cookie ("old-cookie") with the same
    name, scheme, domain, path, and for which either of the following
    conditions is true:

    * The old-cookie's port port-matches the new-cookie.

    * The new-cookie's port port-matches the old-cookie.

    (Notice that this algorithm maintains the invariant that there are
    no two cookies in the cookie store with the same name, scheme,
    domain, and path and for which one cookie's port port-matches the
    other cookie.)

    Then:

    1. If the newly-created cookie was received from a "non-HTTP" API
       and the old-cookie's http-only-flag is true, abort these steps
       and ignore the newly created cookie entirely.

    2. Update the creation-time of the newly-created cookie to match
       the creation-time of the old-cookie.

    3. Remove the old-cookie from the cookie store.
~~~

With cookie storage taken care of now we move onto sending cookies. In
section 5.5 alter step 1 from:

~~~
1.  Let cookie-list be the set of cookies from the cookie store that
    meets all of the following requirements:

    * Either:

      - The cookie's host-only-flag is true and the canonicalized
        request-host is identical to the cookie's domain.

      Or:

      - The cookie's host-only-flag is false and the canonicalized
        request-host domain-matches the cookie's domain.

    * The request-uri's path path-matches the cookie's path.

    * If the cookie's secure-only-flag is true, then the request-uri's
      scheme must denote a "secure" protocol (as defined by the user
      agent).
    
      NOTE: The notion of a "secure" protocol is not defined by this
      document.  Typically, user agents consider a protocol secure if
      the protocol makes use of transport-layer security, such as SSL
      or TLS. For example, most user agents consider "https" to be a
      scheme that denotes a secure protocol.
~~~

to: 

~~~
19. Let cookie-list be the set of cookies from the cookie store that
    meets all of the following requirements:

    * Either:

      - The cookie's host-only-flag is true, and the canonicalized
        request-host is identical to the cookie's domain.

    Or:

      - The cookie's host-only-flag is false, and the canonicalized
        request-host domain-matches the cookie's domain.

    * The request-uri's path path-matches the cookie's path.

    * The request-uri's origin's port component port-matches the
      cookie.

    * The request-uri's origin's scheme component is identical to the
      cookie's scheme
~~~

At which point cookies will be bound to their origin (but have an
ability to cross port thresholds via the Domain attribute if needed).
There are remaining clean up task such as updating the "Weak
Confidentiality" and "Weak Integrity" section, modifying the eviction
algorithm to prefer domain cookies/non-secure schemes, updating
references to Secure (and its uses), etc that will need to tended to
before this can be adopted into a full specs doc. 

## Evict Non-Secure Cookies {#evict-nonsecure}

In the status quo, cookies delivered to non-secure origins are, generally, quite old. Each cookies'
age is somewhat representative of its risk: long-lived cookies expose persistent identifiers to the
network when delivered non-securely which create tracking opportunities over time. Here, we aim to
mitigate this risk by substantially reducing the lifetime of non-secure cookies, thereby limiting
the window of opportunity for network attackers.

This is similar conceptually to previous proposals, notably {{I-D.thomson-http-omnomnom}} and
{{cookies-over-http-bad}}, but seems like it might be more deployable, especially in conjunction
with the scheme changes above.

The change is straightforward, requiring the following text to be added to the bottom of Section
5.4 of {{RFC6265bis}}:

~~~
When "the current session is over", the user agent MUST remove from the cookie store all cookies
whose `scheme` component is non-secure.
~~

As discussed below in {#session-lifetime}, if we add a site-specific session concept, we can make
the following addition:

~~
When "the current session is over" for an origin, the user agent MUST remove from the cookie store
all cookies whose `scheme` component is non-secure, and whose `domain` component's registrable
domain matches the origin's registrable domain.
~~

This still requires the user agent to define a notion of non-secureness, but it would certainly
include "http".


## Session Lifetime {#session-lifetime}

Section 5.4 of {{RFC6265bis}} defines "the current session is over" by choosing not to define it,
instead leaving it up to the user agent. Unfortunately, we have several "session" concepts in user
agents today, and it's not clear that any of them are appropriate for cookies. HTML's
`sessionStorage` lifetime is tied to a particular top-level browsing context, thereby giving two
tabs/windows different views into a page's state. Various user agents' "private mode" create
sessions that are scoped in various ways: Chrome's Incognito mode ties a session's lifetime to the
closure of the last Incognito window, Safari's private mode's lifetime is tab-specific, etc. Session
cookies' lifetime likewise differs between user agents, in some cases based on user-visible settings
like Chrome's "Continue where you left off" (which can lead to quite persistent sessions indeed).

At some risk of further complicating the notion of a "session", it might be reasonable to learn from
existing user agents' work around meeting users' conceptions of when they're using a given site, and
to define a recommended heuristic that user agents could adopt. In particular, Chromium's site
engagement score and Safari's ITP both track a user's last moment of interaction with a site (which
might feasibly include things like navigation, clicks, scrolls, etc). This seems like a useful bit
of data to take into account, along with whether or not a user has top-level browsing contexts that
include a given site.

To that end, we could add a few concepts to {{RFC6265bis}} to give browser vendors more clarity
around a reasonable approach to defining when "the current session is over" for a specific site,
rather that for the browsing session as a whole. Something along the following lines makes sense to
me:

1.  User agents should store a timestamp of the last interaction with a given site in a top-level
    browsing context {{HTML}}. User agents have a great deal of flexibility in what they consider
    an interaction, but typing and clicking should probably count.

2.  Change the "close a browsing context" algorithm {{HTML}} to call the following algorithm between
    its existing step 1 and step 2:

    1.  Let `closedOrigin` be the origin of `browsingContext`'s active document.

    2.  For each top-level browsing context `c`:

        1.  If `c` is `browsingContext`, continue.

        2.  If `c`'s active document's origin is same site with `browsingContext`'s active
            document's origin, return.

    3.  ASSERT: No top-level browsing context contains a document that's same-site with the
        document being closed.

    4.  Return, and continue running this algorithm in parallel.

    5.  Wait however long a user would reasonably expect their state to be retained (an hour
        sounds reasonable).

    5.  For each top-level browsing context `c`:

        1.  If `c`'s active document's origin is same site with `closedOrigin`, return.

    6.  ASSERT: No top-level browsing context contains a document that's same-site with the
        document that was closed.

    7.  Trigger "the current session is over" for `closedOrigin`.

3.  Define a new handler for "the current session is over" that takes an origin into account, and
    clears session cookies for that origin's site.

Note that these definitions refer to "site", not "origin", as cookies span an entire registrable
domain. Ideally, we'll address that too, but not today.


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

Lily Chen has been instrumental in initial deployments of the `SameSite` changes described in 
{{lax-default}} and {{require-secure}}, proving that incremental changes to cookies can be
successfully shipped.

Steven Bingler contributed the "Schemeful SameSite" proposal described in {{schemeful-samesite}}.

