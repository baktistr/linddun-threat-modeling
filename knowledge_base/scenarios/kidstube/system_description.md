# KidsTube — System Description

> Primary evaluation scenario. Source: EPS S26 HW2 (Bakti Satria Adhityatama). Used as the gold-standard baseline.

## Overview

KidsTube is a video-streaming platform for children, operated under parental supervision. Parents create accounts (name, email, password, government-issued ID, six-digit verification code) and create child profiles (name, date of birth, gender, government ID). Children browse, request, watch, like, and comment on videos that parents have approved. The platform tracks children's search and watch history, which parents can review. A planned (not yet implemented) feature would use browsing history to train AI recommendation models and share data with third-party advertisers.

## Stack

React frontend, Node.js/Express backend, MongoDB, local file system storage (backend/uploads/). JWT auth stored in browser localStorage (7-day validity).

## Key Personal Data Assets

- **Parent PII:** full name, email, hashed password, government ID image, six-digit code, profile image
- **Child PII:** name, date of birth, gender, government ID image, avatar
- **Behavioral data:** search history (query, timestamp, result count), watch history (video, duration, completion, timestamp)
- **Content data:** video metadata, comments, likes
- **Account relationships:** parent-child linkage via ObjectId; child actions sent with parent account identifier
- **Auth tokens:** JWT (user ID, user type) in localStorage, 7-day validity
- **System metadata:** IP addresses, device data, timestamps, MongoDB ObjectIds

## DFD Elements

### External Entities
- EE1 Parent User — registers, manages child profiles, uploads/approves videos
- EE2 Child User — browses, requests, watches, likes, comments
- EE3 Third-Party Advertisers — (planned) receive browsing data

### Processes
- P1 Authentication Service — registration, login, JWT generation, password management
- P2 Video Management Service — upload, streaming, search, approval, likes, comments
- P3 Child Profile Management — profile CRUD, search/watch history tracking, request/approval workflow
- P4 AI Recommendation Engine — (planned) trains on browsing history

### Data Stores
- DS1 MongoDB users collection — parent account data
- DS2 MongoDB childprofiles collection — child profiles, search/watch history, requested/approved videos
- DS3 MongoDB videos collection — video metadata, likes, comments, views
- DS4 File System (backend/uploads/) — video files, government ID images, profile images
- DS5 Browser localStorage — JWT token and user data

### Trust Boundaries
- TB1 Internet Boundary — between external users and KidsTube frontend/backend
- TB2 Frontend-Backend Boundary — React frontend to Node.js/Express backend; API calls carry JWT
- TB3 Backend-Database Boundary — backend to MongoDB/file system; MongoDB on localhost with no authentication

### Key Data Flows
- DF1 EE1→P1: parent registration (email, password, name, govt ID, six-digit code)
- DF2 P1→DS1: store parent account
- DF3 P1→EE1: JWT + user data to parent
- DF4 EE2→P1: child login (parent email, password)
- DF5 P1→EE2: JWT (userType child) + child profiles
- DF6 EE1→P3: child profile creation (name, DOB, gender, govt ID)
- DF7 P3→DS2: store/update child profile
- DF8 EE2→P2: video search, request, like, comment
- DF9 P2→DS3/DS4: store/retrieve video metadata and files
- DF10 P3→DS2: store child search and watch history
- DF11 EE1→P2: video upload, approval/rejection
- DF12 P2→EE2: stream approved video to child
- DF13 DS2→P4: child browsing data to AI engine (planned)
- DF14 P4→EE3: browsing data to advertisers (planned)
- DF15 P1→DS4: store government ID images
- DF16 P1→DS5: JWT stored in localStorage
- DF17 P3→EE1: child history retrieved for parent review
