# Intrusion Detection System (IDS) Project
# Author: Ameer Nasrallah

##########################################################
# Normalize PDF Recipe Step Definition
# References: http://cran.nexr.com/web/packages/recipes/vignettes/Custom_Steps.html
#             https://github.com/tidymodels/recipes/blob/main/R/center.R
##########################################################

step_nominalpdf <-
  function(recipe,
           ..., 
           role = NA,
           trained = FALSE,
           ref_dist = NULL,
           skip = FALSE,
           id = rand_id("nominalpdf")) {
    add_step(
      recipe, 
      step_nominalpdf_new(
        terms = enquos(...), 
        trained = trained,
        role = role, 
        ref_dist = ref_dist,
        skip = skip,
        id = id
      )
    )
}

step_nominalpdf_new <-
  function(terms, role, trained, ref_dist, skip, id) {
    step(
      subclass = "nominalpdf", 
      terms = terms,
      role = role,
      trained = trained,
      ref_dist = ref_dist,
      skip = skip,
      id = id
    )
}

prep.step_nominalpdf <- function(x, training, info = NULL, ...) {
  col_names <- recipes_eval_select(x$terms, training, info)
  
  ref_dist <- list()
  train_ln <- nrow(training)
  for (i in col_names) {
    ref_dist[[i]] <- table(training[, i]) / train_ln
  }
  
  ## Always return the updated step
  step_nominalpdf_new(
    terms = x$terms,
    role = x$role,
    trained = TRUE,
    ref_dist = ref_dist,
    skip = x$skip,
    id = x$id
  )
}

pdf_by_ref <- function(x, ref) {
  ifelse(x %in% names(ref), ref[x][[1]], 0)
}

bake.step_nominalpdf <- function(object, new_data, ...) {
  require(tibble)
  ## For illustration (and not speed), we will loop through the affected variables
  ## and do the computations
  vars <- names(object$ref_dist)
  
  for(i in vars) {
    new_data[, i] <- apply(new_data[, i], 1, pdf_by_ref, ref = object$ref_dist[[i]])
  }
  ## Always convert to tibbles on the way out
  tibble::as_tibble(new_data)
}

print.step_nominalpdf <- function(x, width = max(20, options()$width - 30), ...) {
  cat("PDF for ", sep = "")
  printer(names(x$ref_dist), x$terms, x$trained, width = width)
  invisible(x)
}

tidy.step_nominalpdf <- function(x, ...) {
  if (is_trained(x)) {
    res <- tibble(terms = names(x$ref_dist),
                  value = unname(x$ref_dist))
  } else {
    term_names <- sel2char(x$terms)
    res <- tibble(terms = term_names,
                  value = na_dbl)
  }
  res$id <- x$id
  res
}

##########################################################
# Load all required libraries
##########################################################

# if(!require(tidyverse)) install.packages("tidyverse", repos = "http://cran.us.r-project.org")
# if(!require(caret)) install.packages("caret", repos = "http://cran.us.r-project.org")
# if(!require(recipes)) install.packages("recipes", repos = "http://cran.us.r-project.org")
# # to perform parallel computations
# if(!require(doParallel)) install.packages("doParallel", repos = "http://cran.us.r-project.org")
# # to provide multi-class summary
# if(!require(MLmetrics)) install.packages("MLmetrics", repos = "http://cran.us.r-project.org")
# # naive_bayes method required library
# if(!require(naivebayes)) install.packages("naivebayes", repos = "http://cran.us.r-project.org")
# # qda method required library
# if(!require(MASS)) install.packages("MASS", repos = "http://cran.us.r-project.org")
# # svmLinear method required library
# if(!require(kernlab)) install.packages("kernlab", repos = "http://cran.us.r-project.org")
# # gamLoess method required library
# if(!require(gam)) install.packages("gam", repos = "http://cran.us.r-project.org")
# # mlp method required library
# if(!require(RSNNS)) install.packages("RSNNS", repos = "http://cran.us.r-project.org")
# # pcr method required library
# if(!require(pls)) install.packages("pls", repos = "http://cran.us.r-project.org")
# # AdaBoost.M1 method required library
# if(!require(adabag)) install.packages("adabag", repos = "http://cran.us.r-project.org")
# # kknn method required library
# if(!require(kknn)) install.packages("kknn", repos = "http://cran.us.r-project.org")
# # rf method required library
# if(!require(randomForest)) install.packages("randomForest", repos = "http://cran.us.r-project.org")

# To detach any library
# detach("package:libraryX", unload=TRUE)

library(tidyverse)
library(caret)
library(recipes)
library(doParallel)

##########################################################
# Create train set, test set (final hold-out test set)
##########################################################

if (file.exists("data/NSL-KDD.RData")) {
  load("data/NSL-KDD.RData")
} else {
  # Define NSL-KDD column names
  basic_features <- c("duration",
                      "protocol_type",
                      "service",
                      "flag",
                      "src_bytes",
                      "dst_bytes",
                      "land",
                      "wrong_fragment",
                      "urgent")
  
  content_features <- c("hot",
                        "num_failed_logins",
                        "logged_in",
                        "num_compromised",
                        "root_shell",
                        "su_attempted",
                        "num_root",
                        "num_file_creations",
                        "num_shells",
                        "num_access_files",
                        "num_outbound_cmds",
                        "is_host_login",
                        "is_guest_login")
  
  time_based_traffic_features <- c("count",
                                   "srv_count",
                                   "serror_rate",
                                   "srv_serror_rate",
                                   "rerror_rate",
                                   "srv_rerror_rate",
                                   "same_srv_rate",
                                   "diff_srv_rate",
                                   "srv_diff_host_rate")
  
  host_based_traffic_features <- c("dst_host_count",
                                   "dst_host_srv_count",
                                   "dst_host_same_srv_rate",
                                   "dst_host_diff_srv_rate",
                                   "dst_host_same_src_port_rate",
                                   "dst_host_srv_diff_host_rate",
                                   "dst_host_serror_rate",
                                   "dst_host_srv_serror_rate",
                                   "dst_host_rerror_rate",
                                   "dst_host_srv_rerror_rate")
  
  # These are the final column names as specified in the original CSV files
  col_names <- c(basic_features, content_features, time_based_traffic_features, host_based_traffic_features, "label", "difficulty")
  
  nsl_kdd_test_csv = read.csv(file = "https://github.com/jmnwong/NSL-KDD-Dataset/raw/master/KDDTest%2B.txt", col.names = col_names, header = FALSE)
  nsl_kdd_train_csv = read.csv(file = "https://github.com/jmnwong/NSL-KDD-Dataset/raw/master/KDDTrain%2B.txt", col.names = col_names, header = FALSE)
  # Remove difficulty column
  nsl_kdd_train_csv <- nsl_kdd_train_csv %>% select(-difficulty)
  nsl_kdd_test_csv <- nsl_kdd_test_csv %>% select(-difficulty)
  save(nsl_kdd_train_csv, nsl_kdd_test_csv, file = "data/NSL-KDD.RData")
  rm(basic_features, col_names, content_features, host_based_traffic_features, time_based_traffic_features)
}

# str(nsl_kdd_train_csv)
# summary(nsl_kdd_train_csv)

prepare_data <- function(binary_classification, nsl_kdd_train_csv, nsl_kdd_test_csv) {
  if (binary_classification) {
    train_data <- nsl_kdd_train_csv %>%
                    mutate(label = ifelse(label == "normal", "X2", "X1"))
    train_data$label <- factor(train_data$label)
    test_data <- nsl_kdd_test_csv %>%
                  mutate(label = ifelse(label == "normal", "X2", "X1"))
    test_data$label <- factor(test_data$label)
  } else {
    dos_attacks = c("neptune", "back", "land", "pod", "smurf", "teardrop", "mailbomb", "apache2", "processtable", "udpstorm", "worm")
    probing_attacks = c("ipsweep", "nmap", "portsweep", "satan", "mscan", "saint")
    r2l_attacks = c("ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient", "warezmaster", "sendmail", "named", "snmpgetattack", "snmpguess", "xlock", "xsnoop", "httptunnel")
    u2r_attacks = c("buffer_overflow", "loadmodule", "perl", "rootkit", "ps", "sqlattack", "xterm")
    
    label_to_multi_category <- function(label) {
      if (label == "normal") {
        return("X5")
      } else if (label %in% dos_attacks) {
        return("X4")
      } else if (label %in% probing_attacks) {
        return("X3")
      } else if (label %in% r2l_attacks) {
        return("X2")
      } else if (label %in% u2r_attacks) {
        return("X1")
      }
    }
    train_data <- nsl_kdd_train_csv %>%
                    mutate(label = sapply(label, label_to_multi_category))
    train_data$label <- factor(train_data$label)
    test_data <- nsl_kdd_test_csv %>%
                  mutate(label = sapply(label, label_to_multi_category))
    test_data$label <- factor(test_data$label)
    
    rm(dos_attacks, probing_attacks, r2l_attacks, u2r_attacks, label_to_multi_category)
  }
  return(list("train" = train_data, "test" = test_data))
}

classifier_trained_model <- function(model_name, training_data) {
  message(paste(model_name, length(levels(training_data$label))))
  suffix <- ifelse(length(levels(training_data$label)) == 2, "binary", "multi")
  saved_model_path <- paste("data/", paste(model_name, suffix, "fit", sep = "_"), ".rds", sep = "")
  if (file.exists(saved_model_path)) {
    message(paste(model_name, "Reading already trained model from:", saved_model_path))
    model_fit <- readRDS(saved_model_path)
  } else {
    message(paste(model_name, "Did not find a saved model in: ", saved_model_path))
    data_rec <- recipe(label ~ ., data = training_data) %>%
                  step_zv(all_numeric_predictors()) %>%
                  step_range(all_numeric_predictors()) %>%
                  step_nominalpdf(all_nominal_predictors())
    cluster = makePSOCKcluster(detectCores() - 2) # Create a cluster
    registerDoParallel(cluster)
    clusterExport(cl=cluster, varlist=c("step_nominalpdf", "step_nominalpdf_new", "prep.step_nominalpdf", "pdf_by_ref", "bake.step_nominalpdf", "print.step_nominalpdf", "tidy.step_nominalpdf"), envir=environment())
    
    model_fit <- tryCatch({
        set.seed(123)
        model_fit <- train(x = data_rec,
                           data = training_data,
                           method = model_name,
                           trControl = trainControl(method = 'cv', seeds = NULL, summaryFunction = multiClassSummary, classProbs = TRUE))
        saveRDS(model_fit, saved_model_path)
        model_fit
      },
      error = function(cond) {
        message(paste(model_name, "Here's the original error message:", cond))
        return(NULL)
      },
      finally = {
      stopCluster(cluster)
      }
    )
  }
  return(model_fit)
}

classifier_predict <- function(trained_model, testing_data) {
  model_name <- trained_model$method
  suffix <- ifelse(length(levels(testing_data$label)) == 2, "binary", "multi")
  saved_pred_path <- paste("data/", paste(model_name, suffix, "preds", sep = "_"), ".rds", sep = "")
  if (file.exists(saved_pred_path)) {
    message(paste(model_name, "Reading already predicted values from:", saved_pred_path))
    model_pred <- readRDS(saved_pred_path)
  } else {
    message(paste(model_name, "Did not find saved preds in: ", saved_pred_path))
    
    cluster = makePSOCKcluster(detectCores() - 2) # Create a cluster
    registerDoParallel(cluster)
    clusterExport(cl=cluster, varlist=c("step_nominalpdf", "step_nominalpdf_new", "prep.step_nominalpdf", "pdf_by_ref", "bake.step_nominalpdf", "print.step_nominalpdf", "tidy.step_nominalpdf"), envir=environment())
    
    model_pred <- tryCatch({
        set.seed(123)
        if (model_name == "naive_bayes") {
          library(naivebayes)
        } else if (model_name == "parRF") {
          library(randomForest)
        } else {
          library(caret)
        }
        model_pred <- predict(trained_model, testing_data)
        saveRDS(model_pred, saved_pred_path)
        model_pred
      },
      error = function(cond) {
        message(paste(model_name, "Here's the original error message:", cond))
        return(NULL)
      },
      finally = {
        stopCluster(cluster)
      }
    )
  }
  if (!is.null(model_pred)) {
    CM <- tryCatch({
        confusionMatrix(model_pred, testing_data$label)
      },
      error = function(cond) {
        message(paste(model_name, "Here's the original error message:", cond))
        return(NULL)
      }
    )
    return(CM)
  }
  return(NULL)
}

classifiers <- c("rpart", "naive_bayes", "knn", "svmLinear", "parRF", "mlp")

##########################################################
# Classification for binary-label data
##########################################################
binary_class_data <- prepare_data(TRUE, nsl_kdd_train_csv, nsl_kdd_test_csv)
binary_class_models <- lapply(classifiers, classifier_trained_model, training_data = binary_class_data$train)
binary_class_preds <- lapply(binary_class_models, classifier_predict, testing_data = binary_class_data$test)

# binary_class_models[[1]]$modelInfo$label
# binary_class_models[[1]]$modelInfo$library
# binary_class_models[[1]]$modelInfo$type
# binary_class_models[[1]]$modelInfo$parameters
# binary_class_models[[1]]$modelInfo$tags
# binary_class_models[[1]]$results
# binary_class_models[[1]]$bestTune
# binary_class_models[[1]]$times
# plot(binary_class_models[[1]])
# predictors(binary_class_models[[1]]) # not sure if needed
# varImp(binary_class_models[[1]]) # read the docs for further details
# binary_preds <- predict(binary_class_models[[1]], binary_class_data$test)
# confusionMatrix(binary_preds, binary_class_data$test$label)
# Other classifiers: glm, lda, qda, gamLoess, rf

##########################################################
# Classification for multi-label data
##########################################################
multi_class_data <- prepare_data(FALSE, nsl_kdd_train_csv, nsl_kdd_test_csv)
multi_class_models <- lapply(classifiers, classifier_trained_model, training_data = multi_class_data$train)
multi_class_preds <- lapply(multi_class_models, classifier_predict, testing_data = multi_class_data$test)