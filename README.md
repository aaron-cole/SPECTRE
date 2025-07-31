# SPECTRE
Security Profile Editor for Compliance Testing & Regulatory Enforcement

## About SPECTRE
A spectre is an elusive, powerful phantom.  I wanted to create a tool that works behind the scenes to find and fix vulnerabilities before anyone else can see them by using a "True Standard".

As we all know we have encountered in our daily IT duties some sort of security compliance.  We all have sorted through and created our own scripts and routines to check and/or apply these items.
There is a standard for all of this and it's called SCAP (Security Content Automation Protocol).  We all should have heard about it and probably in some form or fashion utilize or see it.
Learning SCAP and the many standards that brings it together is a rugged and rigorous daunting task, that seems like it'll never end.  SCAP creators and editors are non-existent. 
Eyes bleed from looking through an obsence amount of XML.  I go back to words told to me by a mentor of mine - "Don't recreate the wheel".

Enter SPECTRE.  This is my try to at an application for creating and editing SCAP content.  This is to help bring the standard to fruition for IT folks and save time by not having to script things anymore.

The application is a completly python coded software using the SCAP standards.  I took the SCAP standards and created models.  We then use these models and create SCAP content based upon the standards as inputed by the user.

Now anyone can create SCAP!!!!

## The SCAP Standards
I chose these standards to start with, due to my use with the [OSCAP Project](https://www.open-scap.org/) and their openscap-scanner tool.

  - [SCAP 1.2](https://csrc.nist.gov/Projects/security-content-automation-protocol/SCAP-Releases/SCAP-1-2)      
  - [CPE 2.3 Applicability Language](https://csrc.nist.gov/Projects/security-content-automation-protocol/Specifications/cpe/applicability-language)
  - [XCCDF 1.2](https://csrc.nist.gov/Projects/security-content-automation-protocol/Specifications/xccdf)
  - [OVAL 5.11.2](https://github.com/OVAL-Community/OVAL)

Future incorporatation:
  - [OCIL 2.0](https://csrc.nist.gov/Projects/security-content-automation-protocol/Specifications/ocil)
  - Maybe more... who knows how far this will go.


