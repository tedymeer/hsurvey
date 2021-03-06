/****** Object:  Database [HalalCertificationServices]    Script Date: 9/27/2021 12:06:21 PM ******/
CREATE DATABASE [HalalCertificationServices]  (EDITION = 'Basic', SERVICE_OBJECTIVE = 'Basic', MAXSIZE = 2 GB) WITH CATALOG_COLLATION = SQL_Latin1_General_CP1_CI_AS;
GO
ALTER DATABASE [HalalCertificationServices] SET COMPATIBILITY_LEVEL = 150
GO
ALTER DATABASE [HalalCertificationServices] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET ARITHABORT OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [HalalCertificationServices] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [HalalCertificationServices] SET ALLOW_SNAPSHOT_ISOLATION ON 
GO
ALTER DATABASE [HalalCertificationServices] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [HalalCertificationServices] SET READ_COMMITTED_SNAPSHOT ON 
GO
ALTER DATABASE [HalalCertificationServices] SET  MULTI_USER 
GO
ALTER DATABASE [HalalCertificationServices] SET ENCRYPTION ON
GO
ALTER DATABASE [HalalCertificationServices] SET QUERY_STORE = ON
GO
ALTER DATABASE [HalalCertificationServices] SET QUERY_STORE (OPERATION_MODE = READ_WRITE, CLEANUP_POLICY = (STALE_QUERY_THRESHOLD_DAYS = 7), DATA_FLUSH_INTERVAL_SECONDS = 900, INTERVAL_LENGTH_MINUTES = 60, MAX_STORAGE_SIZE_MB = 10, QUERY_CAPTURE_MODE = AUTO, SIZE_BASED_CLEANUP_MODE = AUTO, MAX_PLANS_PER_QUERY = 200, WAIT_STATS_CAPTURE_MODE = ON)
GO
/*** The scripts of database scoped configurations in Azure should be executed inside the target database connection. ***/
GO
-- ALTER DATABASE SCOPED CONFIGURATION SET MAXDOP = 8;
GO
/****** Object:  Table [dbo].[__EFMigrationsHistory]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[__EFMigrationsHistory](
	[MigrationId] [nvarchar](150) NOT NULL,
	[ProductVersion] [nvarchar](32) NOT NULL,
 CONSTRAINT [PK___EFMigrationsHistory] PRIMARY KEY CLUSTERED 
(
	[MigrationId] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Admins]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Admins](
	[AdminId] [int] IDENTITY(1,1) NOT NULL,
	[Name] [nvarchar](max) NOT NULL,
	[Email] [nvarchar](max) NOT NULL,
	[Password] [nvarchar](100) NULL,
	[EmailPassword] [nvarchar](max) NOT NULL,
	[Status] [bit] NOT NULL,
	[Date] [datetime2](7) NOT NULL,
 CONSTRAINT [PK_Admins] PRIMARY KEY CLUSTERED 
(
	[AdminId] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[AspNetRoleClaims]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AspNetRoleClaims](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[RoleId] [nvarchar](450) NOT NULL,
	[ClaimType] [nvarchar](max) NULL,
	[ClaimValue] [nvarchar](max) NULL,
 CONSTRAINT [PK_AspNetRoleClaims] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[AspNetRoles]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AspNetRoles](
	[Id] [nvarchar](450) NOT NULL,
	[Name] [nvarchar](256) NULL,
	[NormalizedName] [nvarchar](256) NULL,
	[ConcurrencyStamp] [nvarchar](max) NULL,
 CONSTRAINT [PK_AspNetRoles] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[AspNetUserClaims]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AspNetUserClaims](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[UserId] [nvarchar](450) NOT NULL,
	[ClaimType] [nvarchar](max) NULL,
	[ClaimValue] [nvarchar](max) NULL,
 CONSTRAINT [PK_AspNetUserClaims] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[AspNetUserLogins]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AspNetUserLogins](
	[LoginProvider] [nvarchar](450) NOT NULL,
	[ProviderKey] [nvarchar](450) NOT NULL,
	[ProviderDisplayName] [nvarchar](max) NULL,
	[UserId] [nvarchar](450) NOT NULL,
 CONSTRAINT [PK_AspNetUserLogins] PRIMARY KEY CLUSTERED 
(
	[LoginProvider] ASC,
	[ProviderKey] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[AspNetUserRoles]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AspNetUserRoles](
	[UserId] [nvarchar](450) NOT NULL,
	[RoleId] [nvarchar](450) NOT NULL,
 CONSTRAINT [PK_AspNetUserRoles] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC,
	[RoleId] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[AspNetUsers]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AspNetUsers](
	[Id] [nvarchar](450) NOT NULL,
	[UserName] [nvarchar](256) NULL,
	[NormalizedUserName] [nvarchar](256) NULL,
	[Email] [nvarchar](256) NULL,
	[NormalizedEmail] [nvarchar](256) NULL,
	[EmailConfirmed] [bit] NOT NULL,
	[PasswordHash] [nvarchar](max) NULL,
	[SecurityStamp] [nvarchar](max) NULL,
	[ConcurrencyStamp] [nvarchar](max) NULL,
	[PhoneNumber] [nvarchar](max) NULL,
	[PhoneNumberConfirmed] [bit] NOT NULL,
	[TwoFactorEnabled] [bit] NOT NULL,
	[LockoutEnd] [datetimeoffset](7) NULL,
	[LockoutEnabled] [bit] NOT NULL,
	[AccessFailedCount] [int] NOT NULL,
 CONSTRAINT [PK_AspNetUsers] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[AspNetUserTokens]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AspNetUserTokens](
	[UserId] [nvarchar](450) NOT NULL,
	[LoginProvider] [nvarchar](450) NOT NULL,
	[Name] [nvarchar](450) NOT NULL,
	[Value] [nvarchar](max) NULL,
 CONSTRAINT [PK_AspNetUserTokens] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC,
	[LoginProvider] ASC,
	[Name] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[AuditDates]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AuditDates](
	[AuditDateId] [int] IDENTITY(1,1) NOT NULL,
	[DateOfAudit] [datetime2](7) NOT NULL,
	[AuditRequestId] [uniqueidentifier] NULL,
	[Status] [bit] NOT NULL,
	[Date] [datetime2](7) NOT NULL,
 CONSTRAINT [PK_AuditDates] PRIMARY KEY CLUSTERED 
(
	[AuditDateId] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[AuditorAuditAssigns]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AuditorAuditAssigns](
	[AuditorAuditAssignId] [int] IDENTITY(1,1) NOT NULL,
	[AuditAcceptRejectStatus] [bit] NOT NULL,
	[AuditRequestId] [uniqueidentifier] NULL,
	[AuditDateId] [int] NULL,
	[AuditorId] [int] NULL,
	[Status] [bit] NOT NULL,
	[Date] [datetime2](7) NOT NULL,
	[AuditRequestStatus] [nvarchar](max) NULL,
 CONSTRAINT [PK_AuditorAuditAssigns] PRIMARY KEY CLUSTERED 
(
	[AuditorAuditAssignId] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Auditors]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Auditors](
	[AuditorId] [int] IDENTITY(1,1) NOT NULL,
	[Name] [nvarchar](max) NOT NULL,
	[Email] [nvarchar](max) NOT NULL,
	[PhoneNumber] [nvarchar](max) NULL,
	[Location] [nvarchar](max) NULL,
	[Status] [bit] NOT NULL,
	[Date] [datetime2](7) NOT NULL,
	[Company] [nvarchar](max) NULL,
 CONSTRAINT [PK_Auditors] PRIMARY KEY CLUSTERED 
(
	[AuditorId] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[AuditRequests]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AuditRequests](
	[AuditRequestId] [uniqueidentifier] NOT NULL,
	[Name] [nvarchar](max) NOT NULL,
	[Description] [nvarchar](max) NULL,
	[AdminId] [int] NULL,
	[Status] [bit] NOT NULL,
	[Date] [datetime2](7) NOT NULL,
	[ARstatus] [nvarchar](max) NULL,
	[Location] [nvarchar](max) NULL,
 CONSTRAINT [PK_AuditRequests] PRIMARY KEY CLUSTERED 
(
	[AuditRequestId] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Remarks]    Script Date: 9/27/2021 12:06:21 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Remarks](
	[RemarkId] [int] IDENTITY(1,1) NOT NULL,
	[AuditRequestId] [uniqueidentifier] NULL,
	[ARremark] [nvarchar](max) NOT NULL,
	[Status] [bit] NOT NULL,
	[Date] [datetime2](7) NOT NULL,
 CONSTRAINT [PK_Remarks] PRIMARY KEY CLUSTERED 
(
	[RemarkId] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
INSERT [dbo].[__EFMigrationsHistory] ([MigrationId], [ProductVersion]) VALUES (N'00000000000000_CreateIdentitySchema', N'3.1.15')
INSERT [dbo].[__EFMigrationsHistory] ([MigrationId], [ProductVersion]) VALUES (N'20210910125323_AddingAllTables', N'3.1.15')
INSERT [dbo].[__EFMigrationsHistory] ([MigrationId], [ProductVersion]) VALUES (N'20210915080424_AddingAuditRequestStatusToAuditorAuditAssign', N'3.1.15')
INSERT [dbo].[__EFMigrationsHistory] ([MigrationId], [ProductVersion]) VALUES (N'20210920122332_AddingRemarksTableARstatusAndCompany', N'3.1.15')
INSERT [dbo].[__EFMigrationsHistory] ([MigrationId], [ProductVersion]) VALUES (N'20210920122543_AddingRemarksTable', N'3.1.15')
INSERT [dbo].[__EFMigrationsHistory] ([MigrationId], [ProductVersion]) VALUES (N'20210923105454_AddingLocationToAuditRequest', N'3.1.15')
GO
SET IDENTITY_INSERT [dbo].[Admins] ON 

INSERT [dbo].[Admins] ([AdminId], [Name], [Email], [Password], [EmailPassword], [Status], [Date]) VALUES (3, N'Halal Certifications', N'halal@gmail.com', N'Halal@123', N'Halal@123', 1, CAST(N'2021-09-19T21:11:31.5975276' AS DateTime2))
SET IDENTITY_INSERT [dbo].[Admins] OFF
GO
INSERT [dbo].[AspNetRoles] ([Id], [Name], [NormalizedName], [ConcurrencyStamp]) VALUES (N'92aa7d7c-5d57-474a-aea5-b2c03e8ebe80', N'Admin', N'ADMIN', N'eaec0ee5-b13b-4a16-8ae1-d079edd6209b')
GO
INSERT [dbo].[AspNetUserRoles] ([UserId], [RoleId]) VALUES (N'35f30bbc-0229-483f-bc3e-82fdbd5b9e04', N'92aa7d7c-5d57-474a-aea5-b2c03e8ebe80')
GO
INSERT [dbo].[AspNetUsers] ([Id], [UserName], [NormalizedUserName], [Email], [NormalizedEmail], [EmailConfirmed], [PasswordHash], [SecurityStamp], [ConcurrencyStamp], [PhoneNumber], [PhoneNumberConfirmed], [TwoFactorEnabled], [LockoutEnd], [LockoutEnabled], [AccessFailedCount]) VALUES (N'35f30bbc-0229-483f-bc3e-82fdbd5b9e04', N'halal@gmail.com', N'HALAL@GMAIL.COM', N'halal@gmail.com', N'HALAL@GMAIL.COM', 1, N'AQAAAAEAACcQAAAAEBxMgv0ZltAnBNc48Pb4Wi9JXAOLezHSLyCRk5ogmq4ZIUiACnT3zvRy5aKSNYmOfA==', N'2JGV2Q3A47HCL265KRTAVD6TJ67DSILY', N'2361060a-8593-4575-aabe-e12e81e52cc4', NULL, 0, 0, NULL, 1, 0)
GO
SET IDENTITY_INSERT [dbo].[AuditDates] ON 

INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (1, CAST(N'2021-09-21T00:00:00.0000000' AS DateTime2), N'6fa3b151-9b31-4406-a6d0-7636f80ca735', 1, CAST(N'2021-09-19T21:16:14.1325671' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (2, CAST(N'2021-09-23T00:00:00.0000000' AS DateTime2), N'6fa3b151-9b31-4406-a6d0-7636f80ca735', 1, CAST(N'2021-09-19T21:16:14.1432651' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (3, CAST(N'2021-09-25T00:00:00.0000000' AS DateTime2), N'6fa3b151-9b31-4406-a6d0-7636f80ca735', 1, CAST(N'2021-09-19T21:16:14.1436691' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (4, CAST(N'2021-09-23T00:00:00.0000000' AS DateTime2), N'967f9831-72e6-4ed2-a717-557c2693d4cc', 1, CAST(N'2021-09-20T06:44:29.6481297' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (5, CAST(N'2021-09-24T00:00:00.0000000' AS DateTime2), N'967f9831-72e6-4ed2-a717-557c2693d4cc', 1, CAST(N'2021-09-20T06:44:29.6567644' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (6, CAST(N'2021-09-27T00:00:00.0000000' AS DateTime2), N'967f9831-72e6-4ed2-a717-557c2693d4cc', 1, CAST(N'2021-09-20T06:44:29.6571350' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (7, CAST(N'2021-09-22T00:00:00.0000000' AS DateTime2), N'09b9a21d-d214-4e85-9878-1273fc211775', 1, CAST(N'2021-09-20T09:42:43.3048673' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (8, CAST(N'2021-09-24T00:00:00.0000000' AS DateTime2), N'09b9a21d-d214-4e85-9878-1273fc211775', 1, CAST(N'2021-09-20T09:42:43.3135043' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (9, CAST(N'2021-09-22T00:00:00.0000000' AS DateTime2), N'7ec267a0-c0cd-43b6-a7af-41fade11ec1c', 1, CAST(N'2021-09-20T09:44:57.4312362' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (10, CAST(N'2021-09-23T00:00:00.0000000' AS DateTime2), N'7ec267a0-c0cd-43b6-a7af-41fade11ec1c', 1, CAST(N'2021-09-20T09:44:57.4314332' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (11, CAST(N'2021-10-20T00:00:00.0000000' AS DateTime2), N'6737ab7b-e448-4a0c-8bed-dab71c307d57', 1, CAST(N'2021-09-21T16:09:22.1221325' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (12, CAST(N'2021-10-21T00:00:00.0000000' AS DateTime2), N'6737ab7b-e448-4a0c-8bed-dab71c307d57', 1, CAST(N'2021-09-21T16:09:22.1301279' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (13, CAST(N'2021-09-23T00:00:00.0000000' AS DateTime2), N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 1, CAST(N'2021-09-22T10:11:43.1269323' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (14, CAST(N'2021-09-24T00:00:00.0000000' AS DateTime2), N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 1, CAST(N'2021-09-22T10:11:43.1277020' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (15, CAST(N'2021-09-25T00:00:00.0000000' AS DateTime2), N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 1, CAST(N'2021-09-22T10:11:43.1277721' AS DateTime2))
INSERT [dbo].[AuditDates] ([AuditDateId], [DateOfAudit], [AuditRequestId], [Status], [Date]) VALUES (16, CAST(N'2021-09-29T00:00:00.0000000' AS DateTime2), N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 1, CAST(N'2021-09-22T16:13:47.4040151' AS DateTime2))
SET IDENTITY_INSERT [dbo].[AuditDates] OFF
GO
SET IDENTITY_INSERT [dbo].[AuditorAuditAssigns] ON 

INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (1, 0, N'6fa3b151-9b31-4406-a6d0-7636f80ca735', 3, 1, 1, CAST(N'2021-09-19T21:17:46.5230509' AS DateTime2), N'Accepted')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (2, 1, N'6fa3b151-9b31-4406-a6d0-7636f80ca735', 2, 1, 1, CAST(N'2021-09-19T21:17:46.5244094' AS DateTime2), N'Rejected')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (3, 0, N'6fa3b151-9b31-4406-a6d0-7636f80ca735', 1, 1, 1, CAST(N'2021-09-19T21:17:46.5245117' AS DateTime2), N'Rejected')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (4, 1, N'967f9831-72e6-4ed2-a717-557c2693d4cc', 6, 1, 1, CAST(N'2021-09-20T06:45:25.2206186' AS DateTime2), N'ReviewedByAuditor')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (5, 0, N'967f9831-72e6-4ed2-a717-557c2693d4cc', 5, 1, 1, CAST(N'2021-09-20T06:45:25.2222977' AS DateTime2), N'Accepted')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (6, 0, N'967f9831-72e6-4ed2-a717-557c2693d4cc', 4, 1, 1, CAST(N'2021-09-20T06:45:25.2223879' AS DateTime2), N'ReviewedByAuditor')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (7, 0, N'09b9a21d-d214-4e85-9878-1273fc211775', 8, 1, 1, CAST(N'2021-09-20T09:42:44.1490976' AS DateTime2), N'Pending')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (8, 0, N'09b9a21d-d214-4e85-9878-1273fc211775', 7, 1, 1, CAST(N'2021-09-20T09:42:44.1421427' AS DateTime2), N'Pending')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (9, 0, N'7ec267a0-c0cd-43b6-a7af-41fade11ec1c', 10, 1, 1, CAST(N'2021-09-20T09:44:57.9451795' AS DateTime2), N'Pending')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (10, 0, N'7ec267a0-c0cd-43b6-a7af-41fade11ec1c', 9, 1, 1, CAST(N'2021-09-20T09:44:57.9446671' AS DateTime2), N'Pending')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (13, 1, N'6737ab7b-e448-4a0c-8bed-dab71c307d57', 12, 5, 1, CAST(N'2021-09-21T16:10:59.6884891' AS DateTime2), N'Accepted')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (14, 1, N'6737ab7b-e448-4a0c-8bed-dab71c307d57', 11, 5, 1, CAST(N'2021-09-21T16:10:59.6897579' AS DateTime2), N'Accepted')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (15, 0, N'6737ab7b-e448-4a0c-8bed-dab71c307d57', 11, 6, 1, CAST(N'2021-09-21T16:09:24.1092725' AS DateTime2), N'Accepted')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (16, 0, N'6737ab7b-e448-4a0c-8bed-dab71c307d57', 12, 6, 1, CAST(N'2021-09-21T16:09:24.1107348' AS DateTime2), N'Accepted')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (17, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 15, 6, 1, CAST(N'2021-09-22T10:11:44.0027932' AS DateTime2), N'Pending')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (18, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 14, 6, 1, CAST(N'2021-09-22T10:11:44.0027080' AS DateTime2), N'Pending')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (19, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 13, 6, 1, CAST(N'2021-09-22T10:11:43.9959596' AS DateTime2), N'Accepted')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (20, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 13, 7, 1, CAST(N'2021-09-22T10:11:44.6719279' AS DateTime2), N'Accepted')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (21, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 14, 7, 1, CAST(N'2021-09-22T10:11:44.6723303' AS DateTime2), N'Accepted')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (22, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 15, 7, 1, CAST(N'2021-09-22T10:11:44.6725539' AS DateTime2), N'Pending')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (23, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 13, 11, 1, CAST(N'2021-09-22T10:11:45.2560145' AS DateTime2), N'Pending')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (24, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 14, 11, 1, CAST(N'2021-09-22T10:11:45.2563780' AS DateTime2), N'Rejected')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (25, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 15, 11, 1, CAST(N'2021-09-22T10:11:45.2565621' AS DateTime2), N'Pending')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (26, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 13, 12, 1, CAST(N'2021-09-22T10:11:45.9024619' AS DateTime2), N'Rejected')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (27, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 14, 12, 1, CAST(N'2021-09-22T10:11:45.9027980' AS DateTime2), N'Accepted')
INSERT [dbo].[AuditorAuditAssigns] ([AuditorAuditAssignId], [AuditAcceptRejectStatus], [AuditRequestId], [AuditDateId], [AuditorId], [Status], [Date], [AuditRequestStatus]) VALUES (28, 0, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', 15, 12, 1, CAST(N'2021-09-22T10:11:45.9029386' AS DateTime2), N'Pending')
SET IDENTITY_INSERT [dbo].[AuditorAuditAssigns] OFF
GO
SET IDENTITY_INSERT [dbo].[Auditors] ON 

INSERT [dbo].[Auditors] ([AuditorId], [Name], [Email], [PhoneNumber], [Location], [Status], [Date], [Company]) VALUES (1, N'Muhammad Waleed', N'muhammad.waleed.010@gmail.com', N'1234567', N'lahore', 1, CAST(N'2021-09-21T13:44:12.9416443' AS DateTime2), N'Smart Information')
INSERT [dbo].[Auditors] ([AuditorId], [Name], [Email], [PhoneNumber], [Location], [Status], [Date], [Company]) VALUES (2, N'Hamza Ismail ', N'hamza@gmail.com', N'123456', N'karachi', 1, CAST(N'2021-09-20T06:42:08.8553400' AS DateTime2), NULL)
INSERT [dbo].[Auditors] ([AuditorId], [Name], [Email], [PhoneNumber], [Location], [Status], [Date], [Company]) VALUES (5, N'Abid Gmail', N'abid.memon@gmail.com', N'03355103456', N'Islamabad', 1, CAST(N'2021-09-21T16:05:26.8924003' AS DateTime2), NULL)
INSERT [dbo].[Auditors] ([AuditorId], [Name], [Email], [PhoneNumber], [Location], [Status], [Date], [Company]) VALUES (6, N'Farhan HCS', N'ftufail@halalcs.org', NULL, N'Lahore', 1, CAST(N'2021-09-21T16:05:59.3922037' AS DateTime2), NULL)
INSERT [dbo].[Auditors] ([AuditorId], [Name], [Email], [PhoneNumber], [Location], [Status], [Date], [Company]) VALUES (7, N'Abid Yahoo', N'abid.memon@yahoo.com', NULL, N'Islamabad', 1, CAST(N'2021-09-21T16:07:29.8283437' AS DateTime2), NULL)
INSERT [dbo].[Auditors] ([AuditorId], [Name], [Email], [PhoneNumber], [Location], [Status], [Date], [Company]) VALUES (8, N'test', N'test@gmail.com', N'12345', N'test', 1, CAST(N'2021-09-21T18:18:58.4829798' AS DateTime2), NULL)
INSERT [dbo].[Auditors] ([AuditorId], [Name], [Email], [PhoneNumber], [Location], [Status], [Date], [Company]) VALUES (9, N'test area guide ', N'testadmisn@gmail.com', N'12345', N'dsfds', 1, CAST(N'2021-09-21T18:19:23.5319450' AS DateTime2), NULL)
INSERT [dbo].[Auditors] ([AuditorId], [Name], [Email], [PhoneNumber], [Location], [Status], [Date], [Company]) VALUES (10, N'test area guide ', N'testadmisn@gmail.com', N'12345', N'dsfds', 0, CAST(N'2021-09-21T18:19:24.4476819' AS DateTime2), NULL)
INSERT [dbo].[Auditors] ([AuditorId], [Name], [Email], [PhoneNumber], [Location], [Status], [Date], [Company]) VALUES (11, N'Farhan Gmial', N'sherdil01@gmail.com', NULL, N'Lahore', 1, CAST(N'2021-09-22T10:08:22.2947881' AS DateTime2), NULL)
INSERT [dbo].[Auditors] ([AuditorId], [Name], [Email], [PhoneNumber], [Location], [Status], [Date], [Company]) VALUES (12, N'Farhan Yahoo', N'ft001@yahoo.com', NULL, N'Lahore', 1, CAST(N'2021-09-22T10:09:02.3973401' AS DateTime2), NULL)
SET IDENTITY_INSERT [dbo].[Auditors] OFF
GO
INSERT [dbo].[AuditRequests] ([AuditRequestId], [Name], [Description], [AdminId], [Status], [Date], [ARstatus], [Location]) VALUES (N'09b9a21d-d214-4e85-9878-1273fc211775', N'Tax Audit Request 20 sep', N'This is demo audit request', 3, 1, CAST(N'2021-09-20T09:42:43.1058496' AS DateTime2), NULL, NULL)
INSERT [dbo].[AuditRequests] ([AuditRequestId], [Name], [Description], [AdminId], [Status], [Date], [ARstatus], [Location]) VALUES (N'7ec267a0-c0cd-43b6-a7af-41fade11ec1c', N'Tax Audit Request ', N'This is demo audit ', 3, 1, CAST(N'2021-09-20T09:44:57.3879780' AS DateTime2), NULL, NULL)
INSERT [dbo].[AuditRequests] ([AuditRequestId], [Name], [Description], [AdminId], [Status], [Date], [ARstatus], [Location]) VALUES (N'967f9831-72e6-4ed2-a717-557c2693d4cc', N'New Auditor Request 20 sep', N'This is demo auditor request', 3, 1, CAST(N'2021-09-20T06:44:29.4699234' AS DateTime2), NULL, NULL)
INSERT [dbo].[AuditRequests] ([AuditRequestId], [Name], [Description], [AdminId], [Status], [Date], [ARstatus], [Location]) VALUES (N'6fa3b151-9b31-4406-a6d0-7636f80ca735', N'test audit request 19 sep', N'this is test audit request to check the errors ', 3, 1, CAST(N'2021-09-19T21:16:14.0345760' AS DateTime2), NULL, NULL)
INSERT [dbo].[AuditRequests] ([AuditRequestId], [Name], [Description], [AdminId], [Status], [Date], [ARstatus], [Location]) VALUES (N'6737ab7b-e448-4a0c-8bed-dab71c307d57', N'Food Audit 2021 ISB', N'Audit is planned for Food & Co on 20th to 21st Oct 2021. Please confirm if you are available on any or all dates.', 3, 1, CAST(N'2021-09-21T16:09:21.8968030' AS DateTime2), N'Ongoing', NULL)
INSERT [dbo].[AuditRequests] ([AuditRequestId], [Name], [Description], [AdminId], [Status], [Date], [ARstatus], [Location]) VALUES (N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', N'HCS Audit in Lahore in September', N'please share your availability for above audit as per below dates', 3, 1, CAST(N'2021-09-22T10:11:42.0000000' AS DateTime2), N'Ongoing', NULL)
GO
SET IDENTITY_INSERT [dbo].[Remarks] ON 

INSERT [dbo].[Remarks] ([RemarkId], [AuditRequestId], [ARremark], [Status], [Date]) VALUES (1, N'6737ab7b-e448-4a0c-8bed-dab71c307d57', N'abid is selected for the audit', 1, CAST(N'2021-09-21T16:21:03.6401824' AS DateTime2))
INSERT [dbo].[Remarks] ([RemarkId], [AuditRequestId], [ARremark], [Status], [Date]) VALUES (3, N'0c816ea9-9222-4fb6-bbc4-df1eeb060d52', N'I have updated and approved as per best availability of auditors', 1, CAST(N'2021-09-22T10:19:26.0605245' AS DateTime2))
INSERT [dbo].[Remarks] ([RemarkId], [AuditRequestId], [ARremark], [Status], [Date]) VALUES (5, N'6737ab7b-e448-4a0c-8bed-dab71c307d57', N'test', 1, CAST(N'2021-09-22T10:21:38.5404695' AS DateTime2))
SET IDENTITY_INSERT [dbo].[Remarks] OFF
GO
/****** Object:  Index [IX_Remarks_AuditRequestId]    Script Date: 9/27/2021 12:06:49 PM ******/
CREATE NONCLUSTERED INDEX [IX_Remarks_AuditRequestId] ON [dbo].[Remarks]
(
	[AuditRequestId] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, DROP_EXISTING = OFF, ONLINE = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
ALTER TABLE [dbo].[AspNetRoleClaims]  WITH CHECK ADD  CONSTRAINT [FK_AspNetRoleClaims_AspNetRoles_RoleId] FOREIGN KEY([RoleId])
REFERENCES [dbo].[AspNetRoles] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[AspNetRoleClaims] CHECK CONSTRAINT [FK_AspNetRoleClaims_AspNetRoles_RoleId]
GO
ALTER TABLE [dbo].[AspNetUserClaims]  WITH CHECK ADD  CONSTRAINT [FK_AspNetUserClaims_AspNetUsers_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[AspNetUsers] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[AspNetUserClaims] CHECK CONSTRAINT [FK_AspNetUserClaims_AspNetUsers_UserId]
GO
ALTER TABLE [dbo].[AspNetUserLogins]  WITH CHECK ADD  CONSTRAINT [FK_AspNetUserLogins_AspNetUsers_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[AspNetUsers] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[AspNetUserLogins] CHECK CONSTRAINT [FK_AspNetUserLogins_AspNetUsers_UserId]
GO
ALTER TABLE [dbo].[AspNetUserRoles]  WITH CHECK ADD  CONSTRAINT [FK_AspNetUserRoles_AspNetRoles_RoleId] FOREIGN KEY([RoleId])
REFERENCES [dbo].[AspNetRoles] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[AspNetUserRoles] CHECK CONSTRAINT [FK_AspNetUserRoles_AspNetRoles_RoleId]
GO
ALTER TABLE [dbo].[AspNetUserRoles]  WITH CHECK ADD  CONSTRAINT [FK_AspNetUserRoles_AspNetUsers_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[AspNetUsers] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[AspNetUserRoles] CHECK CONSTRAINT [FK_AspNetUserRoles_AspNetUsers_UserId]
GO
ALTER TABLE [dbo].[AspNetUserTokens]  WITH CHECK ADD  CONSTRAINT [FK_AspNetUserTokens_AspNetUsers_UserId] FOREIGN KEY([UserId])
REFERENCES [dbo].[AspNetUsers] ([Id])
ON DELETE CASCADE
GO
ALTER TABLE [dbo].[AspNetUserTokens] CHECK CONSTRAINT [FK_AspNetUserTokens_AspNetUsers_UserId]
GO
ALTER TABLE [dbo].[AuditDates]  WITH CHECK ADD  CONSTRAINT [FK_AuditDates_AuditRequests_AuditRequestId] FOREIGN KEY([AuditRequestId])
REFERENCES [dbo].[AuditRequests] ([AuditRequestId])
GO
ALTER TABLE [dbo].[AuditDates] CHECK CONSTRAINT [FK_AuditDates_AuditRequests_AuditRequestId]
GO
ALTER TABLE [dbo].[AuditorAuditAssigns]  WITH CHECK ADD  CONSTRAINT [FK_AuditorAuditAssigns_AuditDates_AuditDateId] FOREIGN KEY([AuditDateId])
REFERENCES [dbo].[AuditDates] ([AuditDateId])
GO
ALTER TABLE [dbo].[AuditorAuditAssigns] CHECK CONSTRAINT [FK_AuditorAuditAssigns_AuditDates_AuditDateId]
GO
ALTER TABLE [dbo].[AuditorAuditAssigns]  WITH CHECK ADD  CONSTRAINT [FK_AuditorAuditAssigns_Auditors_AuditorId] FOREIGN KEY([AuditorId])
REFERENCES [dbo].[Auditors] ([AuditorId])
GO
ALTER TABLE [dbo].[AuditorAuditAssigns] CHECK CONSTRAINT [FK_AuditorAuditAssigns_Auditors_AuditorId]
GO
ALTER TABLE [dbo].[AuditorAuditAssigns]  WITH CHECK ADD  CONSTRAINT [FK_AuditorAuditAssigns_AuditRequests_AuditRequestId] FOREIGN KEY([AuditRequestId])
REFERENCES [dbo].[AuditRequests] ([AuditRequestId])
GO
ALTER TABLE [dbo].[AuditorAuditAssigns] CHECK CONSTRAINT [FK_AuditorAuditAssigns_AuditRequests_AuditRequestId]
GO
ALTER TABLE [dbo].[AuditRequests]  WITH CHECK ADD  CONSTRAINT [FK_AuditRequests_Admins_AdminId] FOREIGN KEY([AdminId])
REFERENCES [dbo].[Admins] ([AdminId])
GO
ALTER TABLE [dbo].[AuditRequests] CHECK CONSTRAINT [FK_AuditRequests_Admins_AdminId]
GO
ALTER TABLE [dbo].[Remarks]  WITH CHECK ADD  CONSTRAINT [FK_Remarks_AuditRequests_AuditRequestId] FOREIGN KEY([AuditRequestId])
REFERENCES [dbo].[AuditRequests] ([AuditRequestId])
GO
ALTER TABLE [dbo].[Remarks] CHECK CONSTRAINT [FK_Remarks_AuditRequests_AuditRequestId]
GO
ALTER DATABASE [HalalCertificationServices] SET  READ_WRITE 
GO
