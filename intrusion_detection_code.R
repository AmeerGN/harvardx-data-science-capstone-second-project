# Intrusion Detection System (IDS) Project
# Author: Ameer Nasrallah

##########################################################
# Libraries needed
##########################################################

# if(!require(tidyverse)) install.packages("tidyverse", repos = "http://cran.us.r-project.org")
# if(!require(caret)) install.packages("caret", repos = "http://cran.us.r-project.org")
# if(!require(recipes)) install.packages("recipes", repos = "http://cran.us.r-project.org")
# # to perform parallel computations
# if(!require(doParallel)) install.packages("doParallel", repos = "http://cran.us.r-project.org")
# if(!require(knitr)) install.packages("knitr", repos = "http://cran.us.r-project.org")
# if(!require(kableExtra)) install.packages("kableExtra", repos = "http://cran.us.r-project.org")
# # to provide multi-class summary
# if(!require(MLmetrics)) install.packages("MLmetrics", repos = "http://cran.us.r-project.org")
# # naive_bayes method required library
# if(!require(naivebayes)) install.packages("naivebayes", repos = "http://cran.us.r-project.org")
# # svmLinear method required library
# if(!require(kernlab)) install.packages("kernlab", repos = "http://cran.us.r-project.org")
# # mlp method required library
# if(!require(RSNNS)) install.packages("RSNNS", repos = "http://cran.us.r-project.org")
# parRF method required library
# if(!require(randomForest)) install.packages("randomForest", repos = "http://cran.us.r-project.org")
# if(!require(matrixStats)) install.packages("matrixStats", repos = "http://cran.us.r-project.org")

library(tidyverse)
library(caret)
library(recipes)
library(doParallel)
library(knitr)
library(kableExtra)

##########################################################
# Create train set, test set (final hold-out test set)
##########################################################

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

if (file.exists("data/NSL-KDD.RData")) {
  load("data/NSL-KDD.RData")
} else {
  nsl_kdd_train_csv = read.csv(unz("data/NSL-KDD.zip", "KDDTrain+.txt"), col.names = col_names, header = FALSE)
  nsl_kdd_test_csv = read.csv(unz("data/NSL-KDD.zip", "KDDTest+.txt"), col.names = col_names, header = FALSE)
  # Remove difficulty column
  nsl_kdd_train_csv <- nsl_kdd_train_csv %>% select(-difficulty)
  nsl_kdd_test_csv <- nsl_kdd_test_csv %>% select(-difficulty)
  save(nsl_kdd_train_csv, nsl_kdd_test_csv, file = "data/NSL-KDD.RData")
}

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
binary_class_data <- prepare_data(TRUE, nsl_kdd_train_csv, nsl_kdd_test_csv)
multi_class_data <- prepare_data(FALSE, nsl_kdd_train_csv, nsl_kdd_test_csv)

##########################################################
# Attacks category table
##########################################################

dos_attacks = c("neptune", "back", "land", "pod", "smurf", "teardrop", "mailbomb", "apache2", "processtable", "udpstorm", "worm")
probing_attacks = c("ipsweep", "nmap", "portsweep", "satan", "mscan", "saint")
r2l_attacks = c("ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient", "warezmaster", "sendmail", "named", "snmpgetattack", "snmpguess", "xlock", "xsnoop", "httptunnel")
u2r_attacks = c("buffer_overflow", "loadmodule", "perl", "rootkit", "ps", "sqlattack", "xterm")

attacks_categories <- c(paste(dos_attacks, collapse = ", "), paste(probing_attacks, collapse = ", "), paste(r2l_attacks, collapse = ", "), paste(u2r_attacks, collapse = ", "))
attacks_df <- data.frame(c("DoS", "Probing", "R2L", "U2R"), attacks_categories)
colnames(attacks_df) <- c("Attack Category", "Attacks Included")
attacks_df %>% kbl(caption = "NSL-KDD Attacks Categories") %>%
  kable_styling(latex_options = c("HOLD_position"), position = "center") %>%
  column_spec(1, border_left = T) %>%
  column_spec(2, width = "30em",border_right = T) %>%
  row_spec(0, bold = T)

##########################################################
# Distribution of Normal/Attacks in NSL-KDD Training and Testing Sets
##########################################################

training_multi_label <- multi_class_data$train %>%
  select(label) %>%
  mutate(set = "Training Set")
testing_multi_label <- multi_class_data$test %>%
  select(label) %>%
  mutate(set = "Testing Set")
rbind(training_multi_label, testing_multi_label) %>%
  mutate(multi_label = case_when(label == "X1" ~ "U2R",
                                 label == "X2" ~ "R2L",
                                 label == "X3" ~ "Probing",
                                 label == "X4" ~ "DoS",
                                 label == "X5" ~ "Normal")) %>%
  ggplot(aes(x = fct_infreq(multi_label), group = set)) +
  geom_bar(aes(y = ..prop..), stat = "count") +
  geom_label(aes(label = scales::percent(..prop..), y = ..prop..), stat = "count", vjust = "outward", size = 3.5) +
  geom_label(aes(label = ..count.., y = ..prop..), stat = "count", vjust = "inward", size = 3.5) +
  facet_grid(~factor(set, levels = c("Training Set", "Testing Set"))) +
  scale_y_continuous(labels = scales::percent) +
  labs(x = "Label", y = "Frequency")

##########################################################
# NSL-KDD Attributes
##########################################################

features_df_transformer <- function(features_names, category_name) {
  custom_col_summary <- function(col) {
    # if the column is not numeric, then we will print all its unique values separated by a comma
    # if the column is numeric and has only two values, we will print those values separated by a comma
    # if the column is numeric and has many values, we will print it as min-max
    return(tibble("Type" = class(col), "Range or Values" = ifelse(is.numeric(col), paste(min(col), max(col), sep = ifelse(length(unique(col)) == 2, ",", "-")), paste(unique(col), collapse = ", "))))
  }
  # we replicated the category to use it in collapse_rows in kbl
  df <- cbind("Category" = replicate(length(features_names), category_name), "Feature" = features_names, bind_rows(lapply(X = nsl_kdd_train_csv[, features_names], FUN = custom_col_summary)))
  df
}

basic_df <- features_df_transformer(basic_features, "Basic features")
content_df <- features_df_transformer(content_features, "Content features")
time_based_traffic_df <- features_df_transformer(time_based_traffic_features, "Time-based traffic features")
host_based_traffic_df <- features_df_transformer(host_based_traffic_features, "Connection-based traffic features")
atts_df <- rbind(basic_df, content_df, time_based_traffic_df, host_based_traffic_df)

atts_df %>% kbl(caption = "NSL-KDD Attributes", col.names = c("Category", "Feature", "Type", "Range/Values"), centering = F) %>%
  kable_styling(position = "left", latex_options = c("HOLD_position")) %>%
  column_spec(1, width = "4.8em", border_left = T) %>%
  column_spec(2, width = "13.5em") %>%
  column_spec(3, width = "3.7em") %>%
  column_spec(4, width = "26.5em", border_right = T) %>%
  row_spec(0, bold = T) %>%
  collapse_rows(1, valign = "middle")

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
    # For each column, table will return the count of each value
    # to normalize that count, we divide it by the number of rows
    # For example, if we have (a, b, a, c, d) in a column
    # The output will be a table like this
    #   a   b   c   d 
    # 0.4 0.2 0.2 0.2
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
  # if we have the following values in ref:
  #   a   b   c   d 
  # 0.4 0.2 0.2 0.2
  # And we got x = "a", the function will return 0.4
  # if we got x = "e", the function will return 0
  ifelse(x %in% names(ref), ref[x][[1]], 0)
}

bake.step_nominalpdf <- function(object, new_data, ...) {
  require(tibble)
  vars <- names(object$ref_dist)
  
  # Transform the columns
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
# Classifiers Description
##########################################################

classifiers_desc <- data.frame(c("Recursive Partitioning", "Naive Bayes", "KNN", "SVM", "Random Forest", "Multi-Layer Perceptron"), c("rpart", "naive_bayes", "knn", "svmLinear", "parRF", "mlp"), c("rpart::rpart (ref:terry2019Rpart)", "naivebayes::naive_bayes (ref:michal2019naivebayes)", "caret::knn3", "kernlab::ksvm (ref:alexandros2004kernlab)", "randomForest::randomForest (ref:andy2002rf)", "RSNNS::mlp (ref:christoph2012mlp)"), c("cp", "laplace, usekernel, adjust", "k", "C", "mtry", "size"))

classifiers_desc %>% kbl(caption = "Classifiers Description", col.names = c("Classifier Name", "Caret Name", "Package::Function", "Parameters")) %>%
  kable_styling(latex_options = c("HOLD_position")) %>%
  column_spec(1, border_left = T) %>%
  column_spec(4, border_right = T) %>%
  row_spec(0, bold = T)

##########################################################
# Classifiers definition and training and prediction functions
##########################################################

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
    # Create a cluster
    cluster = makePSOCKcluster(detectCores() - 2)
    # Register the cluster
    registerDoParallel(cluster)
    # Register the functions related to step_nominalpdf to the cluster
    clusterExport(cl=cluster, varlist=c("step_nominalpdf", "step_nominalpdf_new", "prep.step_nominalpdf", "pdf_by_ref", "bake.step_nominalpdf", "print.step_nominalpdf", "tidy.step_nominalpdf"), envir=environment())
    
    model_fit <- tryCatch({
        set.seed(123)
        # Setting the seeds to NULL, this way caret will automatically generate the seeds for 'cv' based on the seed we set
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
    
    # Create a cluster
    cluster = makePSOCKcluster(detectCores() - 2)
    # Register the cluster
    registerDoParallel(cluster)
    # Register the functions related to step_nominalpdf to the cluster
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

# Tuning table
tuning_table <- function(model) {
  return(tibble(method = model$method,
                parameters = paste(paste(colnames(model$bestTune), model$bestTune, sep = " = "), collapse = ", "),
                accuracy = model$results[rownames(model$bestTune), c("Accuracy")],
                tuning = model$times$everything[[3]] - model$times$final[[3]]))
}
bind_rows(lapply(X = binary_class_models, FUN = tuning_table)) %>%
  kbl(caption = "Binary Classification IDS Parameters Tuning", col.names = c("Classifier", "Best Tuned Parameters", "Accuracy", "Tuning Time (seconds)")) %>%
  kable_styling(latex_options = c("HOLD_position"), position = "center") %>%
  column_spec(1, border_left = T) %>%
  column_spec(4, border_right = T) %>%
  row_spec(0, bold = T)

# Training time
times_transformer <- function(model) {
  return(tibble("classifier" = model$method, "everything" = model$times$everything[[3]], "final" = model$times$final[[3]]))
}
binary_classifiers_times <- bind_rows(lapply(X = binary_class_models, FUN = times_transformer))
binary_classifiers_times %>%
  ggplot(aes(x = classifier, y = final)) +
  geom_bar(stat = "identity") +
  geom_label(aes(label = sprintf('%0.5f', final))) +
  scale_y_log10() +
  labs(x = "Classifier", y = "Time (seconds)")

# rpart var imp
ggplot(varImp(binary_class_models[[1]]), top = 5)

# parRF var imp
ggplot(varImp(binary_class_models[[5]]), top = 5)

# binary metrics
binary_metrics_tibble <- function(idx) {
  cls_TP <- binary_class_preds[[idx]]$table[1,1]
  cls_FP <- binary_class_preds[[idx]]$table[1,2]
  cls_FN <- binary_class_preds[[idx]]$table[2,1]
  cls_TN <- binary_class_preds[[idx]]$table[2,2]
  return(tibble(classifier = classifiers[idx], accuracy = binary_class_preds[[idx]]$overall["Accuracy"][[1]], TP = cls_TP, FP = cls_FP, FN = cls_FN, TN = cls_TN))
}
binary_metrics <- data.frame(bind_rows(lapply(X = seq_along(classifiers), FUN = binary_metrics_tibble))) %>%
  mutate(detection_rate = TP / (TP + FN),  far = FP / (FP + TN))

# accuracy graph
binary_metrics %>%
  ggplot(aes(x = classifier, y = accuracy)) +
  geom_bar(stat = "identity") +
  geom_label(aes(label = sprintf('%0.5f', accuracy), fontface = ifelse(accuracy == max(accuracy), 2, 1)), vjust = "inward") +
  labs(x = "Classifier", y = "Accuracy")

# FAR graph
binary_metrics %>%
  ggplot(aes(x = classifier, y = far)) +
  geom_bar(stat = "identity") +
  geom_label(aes(label = sprintf('%0.5f', far), fontface = ifelse(far == invoke(pmin, na_if(far, 0), na.rm = TRUE), 2, 1)), vjust = "inward") +
  labs(x = "Classifier", "False Alarm Rate (FAR)")

# DR graph
binary_metrics %>%
  ggplot(aes(x = classifier, y = detection_rate)) +
  geom_bar(stat = "identity") +
  geom_label(aes(label = sprintf('%0.5f', detection_rate), fontface = ifelse(detection_rate == max(detection_rate), 2, 1)), vjust = "inward") +
  labs(x = "Classifier", "Detection Rate (DR")

##########################################################
# Classification for multi-label data
##########################################################

multi_class_data <- prepare_data(FALSE, nsl_kdd_train_csv, nsl_kdd_test_csv)
multi_class_models <- lapply(classifiers, classifier_trained_model, training_data = multi_class_data$train)
multi_class_preds <- lapply(multi_class_models, classifier_predict, testing_data = multi_class_data$test)

# Tuning table
bind_rows(lapply(X = multi_class_models, FUN = tuning_table)) %>%
  kbl(caption = "Multi-class Classification Tuning", col.names = c("Classifier", "Best Tuned Parameters", "Accuracy", "Tuning Time (seconds)")) %>%
  kable_styling(latex_options = c("HOLD_position"), position = "center") %>%
  column_spec(1, border_left = T) %>%
  column_spec(4, border_right = T) %>%
  row_spec(0, bold = T)

# Training time
multi_classifiers_times <- bind_rows(lapply(X = multi_class_models, FUN = times_transformer))
multi_classifiers_times %>%
  ggplot(aes(x = classifier, y = final)) +
  geom_bar(stat = "identity") +
  geom_label(aes(label = sprintf('%0.5f', final))) +
  scale_y_log10() +
  labs(x = "Classifier", y = "Time (seconds)")

# rpart var imp
ggplot(varImp(multi_class_models[[1]]), top = 5)

# parRF var imp
ggplot(varImp(multi_class_models[[5]]), top = 5)

# multi metrics
multi_class_preds <- lapply(multi_class_models, classifier_predict, testing_data = multi_class_data$test)
accuracy_tibble <- function(idx) {
  return(tibble(classifier = classifiers[idx], accuracy = multi_class_preds[[idx]]$overall["Accuracy"][[1]]))
}
multi_acc <- data.frame(bind_rows(lapply(X = seq_along(classifiers), FUN = accuracy_tibble)))
metrics_calculator <- function(idx) {
  mtrx <- multi_class_preds[[idx]]$table
  mtrx_row_sums <- rowSums(mtrx)
  mtrx_col_sum <- colSums(mtrx)
  mtrx_diag_sum <- sum(diag(mtrx))
  mtrx_sum <- sum(mtrx)
  metric <- function(cls) {
    cls_TP <- mtrx[cls, cls]
    cls_FP <- mtrx_row_sums[cls][[1]] - mtrx[cls, cls]
    cls_FN <- mtrx_col_sum[cls][[1]] - mtrx[cls, cls]
    cls_TN <- mtrx_sum - (cls_TP + cls_FP + cls_FN)
    return(tibble(classifier = classifiers[idx], class = cls, TP = cls_TP, FP = cls_FP, FN = cls_FN, TN = cls_TN))
  }
  return(bind_rows(lapply(X = c("X1", "X2", "X3", "X4", "X5"), FUN = metric)))
}
multi_metrics <- data.frame(bind_rows(lapply(X = seq_along(classifiers), FUN = metrics_calculator))) %>%
  mutate(multi_label = case_when(class == "X1" ~ "U2R",
                                 class == "X2" ~ "R2L",
                                 class == "X3" ~ "Probing",
                                 class == "X4" ~ "DoS",
                                 class == "X5" ~ "Normal")) %>%
  mutate(detection_rate = TP / (TP + FN),  far = FP / (FP + TN)) %>%
  group_by(multi_label) %>%
  mutate(max_dr = max(detection_rate), min_far = invoke(pmin, na_if(far, 0), na.rm = TRUE))

# accuracy graph
multi_acc %>%
  ggplot(aes(x = classifier, y = accuracy)) +
  geom_bar(stat = "identity") +
  geom_label(aes(label = sprintf('%0.5f', accuracy), fontface = ifelse(accuracy == max(accuracy), 2, 1)), vjust = "inward") +
  labs(x = "Classifier", y = "Accuracy")

# FAR graph
multi_metrics %>%
  filter(multi_label != "Normal") %>%
  ggplot(aes(x = classifier, y = far)) +
  geom_bar(stat = "identity") +
  geom_label(aes(label = sprintf('%0.5f', far), fontface = ifelse(far == min_far, 2, 1)), vjust = "inward") +
  facet_grid(multi_label~.) +
  labs(x = "Classifier", y = "False Alarm Rate (FAR)")

# DR graph
multi_metrics %>%
  filter(multi_label != "Normal") %>%
  ggplot(aes(x = classifier, y = detection_rate)) +
  geom_bar(stat = "identity") +
  geom_label(aes(label = sprintf('%0.5f', detection_rate), fontface = ifelse(detection_rate == max_dr, 2, 1)), vjust = "inward") +
  facet_grid(multi_label~.) +
  labs(x = "Classifier", y = "Detection Rate (DR)")